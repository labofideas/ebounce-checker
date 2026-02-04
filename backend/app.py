import csv
import io
import os
import re
import time
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import dns.resolver
from email_validator import EmailNotValidError, validate_email

TEST_MODE = os.environ.get("EBOUNCE_TEST_MODE") == "1"

if TEST_MODE:
    class _DummyApp:
        def get(self, *args, **kwargs):
            return lambda fn: fn
        def post(self, *args, **kwargs):
            return lambda fn: fn
    def _dummy(*args, **kwargs):
        return None
    BackgroundTasks = object
    Body = File = Form = _dummy
    UploadFile = object
    FileResponse = HTMLResponse = JSONResponse = StreamingResponse = object
    app = _DummyApp()
else:
    from fastapi import BackgroundTasks, Body, FastAPI, File, Form, UploadFile
    from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
    app = FastAPI(title="Ebounce Checker")

DATA_DIR = "/tmp/ebounce_checker"
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "jobs.db")
MAX_SMTP_WORKERS = 5
SMTP_DELAY_SEC = 0.2

EMAIL_REGEX = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
COMMON_EMAIL_HEADERS = {"email", "email_address", "e-mail", "mail"}



@dataclass
class DomainInfo:
    status: str  # domain_mx | domain_no_mx | domain_unknown
    mx_hosts: List[str]
    reason: str


JOBS: Dict[str, Dict] = {}


def init_db():
    import sqlite3
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                created_at REAL,
                dir TEXT,
                status TEXT,
                phase TEXT,
                processed INTEGER,
                total_rows INTEGER,
                last_smtp_batch_at REAL
            )
            """
        )
        conn.commit()


def load_jobs_from_db():
    import sqlite3
    if not os.path.exists(DB_PATH):
        return
    with sqlite3.connect(DB_PATH) as conn:
        for row in conn.execute("SELECT job_id, created_at, dir, status, phase, processed, total_rows, last_smtp_batch_at FROM jobs"):
            job_id, created_at, dir_path, status, phase, processed, total_rows, last_smtp_batch_at = row
            if job_id not in JOBS and os.path.isdir(dir_path):
                JOBS[job_id] = {
                    "created_at": created_at,
                    "dir": dir_path,
                    "downloads": {},
                    "summary": {},
                    "status": status or "complete",
                    "phase": phase or "done",
                    "processed": processed or 0,
                    "total_rows": total_rows or 0,
                    "last_smtp_batch_at": last_smtp_batch_at,
                }
                recompute_summary(job_id)


def persist_job(job_id: str):
    import sqlite3
    job = JOBS.get(job_id)
    if not job:
        return
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO jobs (job_id, created_at, dir, status, phase, processed, total_rows, last_smtp_batch_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id) DO UPDATE SET
                created_at=excluded.created_at,
                dir=excluded.dir,
                status=excluded.status,
                phase=excluded.phase,
                processed=excluded.processed,
                total_rows=excluded.total_rows,
                last_smtp_batch_at=excluded.last_smtp_batch_at
            """,
            (
                job_id,
                job.get("created_at"),
                job.get("dir"),
                job.get("status"),
                job.get("phase"),
                job.get("processed", 0),
                job.get("total_rows", 0),
                job.get("last_smtp_batch_at"),
            ),
        )
        conn.commit()


def normalize_email(value: str) -> Optional[str]:
    value = value.strip()
    if not value:
        return None
    try:
        v = validate_email(value, check_deliverability=False)
        return v.normalized
    except EmailNotValidError:
        return None


def detect_email_column(
    headers: List[str],
    explicit: Optional[str],
    no_header: bool,
    row_width: Optional[int],
) -> Optional[int]:
    if explicit:
        if explicit.strip().isdigit():
            idx = int(explicit.strip()) - 1
            if idx >= 0 and (row_width is None or idx < row_width):
                return idx
        if not no_header:
            for idx, h in enumerate(headers):
                if h.strip().lower() == explicit.strip().lower():
                    return idx
    if not no_header:
        for idx, h in enumerate(headers):
            if h.strip().lower() in COMMON_EMAIL_HEADERS:
                return idx
    if row_width == 1 or len(headers) == 1:
        return 0
    return None


def extract_emails_from_row(row: List[str], col_idx: Optional[int]) -> List[str]:
    values = []
    if col_idx is not None and col_idx < len(row):
        values = [row[col_idx]]
    else:
        values = row

    found: List[str] = []
    for cell in values:
        if not cell:
            continue
        for match in EMAIL_REGEX.findall(cell):
            found.append(match)
    # keep order, remove exact duplicates in-row
    seen = set()
    result = []
    for email in found:
        if email not in seen:
            seen.add(email)
            result.append(email)
    return result


def resolve_domain(domain: str, resolver: dns.resolver.Resolver, cache: Dict[str, DomainInfo]) -> DomainInfo:
    if domain in cache:
        return cache[domain]
    try:
        answers = resolver.resolve(domain, "MX")
        mx_hosts = sorted({str(r.exchange).rstrip(".") for r in answers})
        info = DomainInfo("domain_mx", mx_hosts, "MX found")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        # fallback to A/AAAA for RFC compliance
        try:
            resolver.resolve(domain, "A")
            info = DomainInfo("domain_no_mx", [], "No MX; A record exists")
        except Exception:
            try:
                resolver.resolve(domain, "AAAA")
                info = DomainInfo("domain_no_mx", [], "No MX; AAAA record exists")
            except Exception:
                info = DomainInfo("domain_no_mx", [], "No MX or A/AAAA records")
    except dns.exception.Timeout:
        info = DomainInfo("domain_unknown", [], "DNS timeout")
    except Exception as exc:
        info = DomainInfo("domain_unknown", [], f"DNS error: {exc}")

    cache[domain] = info
    return info


def resolve_spf(domain: str, resolver: dns.resolver.Resolver, cache: Dict[str, str]) -> str:
    if domain in cache:
        return cache[domain]
    try:
        answers = resolver.resolve(domain, "TXT")
        for r in answers:
            txt = "".join([t.decode() if isinstance(t, bytes) else t for t in r.strings])
            if txt.lower().startswith("v=spf1"):
                cache[domain] = "spf_present"
                return cache[domain]
        cache[domain] = "spf_missing"
        return cache[domain]
    except Exception:
        cache[domain] = "spf_unknown"
        return cache[domain]


def resolve_dmarc(domain: str, resolver: dns.resolver.Resolver, cache: Dict[str, str]) -> str:
    if domain in cache:
        return cache[domain]
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_domain, "TXT")
        for r in answers:
            txt = "".join([t.decode() if isinstance(t, bytes) else t for t in r.strings])
            if txt.lower().startswith("v=dmarc1"):
                cache[domain] = "dmarc_present"
                return cache[domain]
        cache[domain] = "dmarc_missing"
        return cache[domain]
    except Exception:
        cache[domain] = "dmarc_unknown"
        return cache[domain]


def classify_label(status: str) -> str:
    if status in {"invalid_syntax", "smtp_undeliverable"}:
        return "Invalid"
    if status in {"domain_no_mx", "smtp_unknown"}:
        return "Risky"
    if status in {"domain_mx", "smtp_deliverable"}:
        return "Safe"
    if status == "duplicate":
        return "Duplicate"
    return "Unknown"


def smtp_probe(email: str, mx_hosts: List[str]) -> Tuple[str, str]:
    import smtplib

    if not mx_hosts:
        return "smtp_unknown", "No MX hosts"

    for host in mx_hosts:
        try:
            with smtplib.SMTP(host, 25, timeout=10) as server:
                server.ehlo_or_helo_if_needed()
                code, _ = server.mail("checker@local.test")
                if code >= 400:
                    return "smtp_unknown", f"MAIL FROM rejected ({code})"
                code, resp = server.rcpt(email)
                message = resp.decode(errors="ignore") if isinstance(resp, bytes) else str(resp)
                if code in (250, 251):
                    return "smtp_deliverable", f"RCPT accepted ({code})"
                if code in (550, 551, 553, 554):
                    return "smtp_undeliverable", f"RCPT rejected ({code})"
                if code in (421, 450, 451, 452):
                    return "smtp_unknown", f"Temporary response ({code})"
                return "smtp_unknown", f"SMTP response ({code})"
        except Exception as exc:
            last_error = str(exc)
            continue

    return "smtp_unknown", f"Connection failed: {last_error}" if "last_error" in locals() else "Connection failed"


def update_job(job_id: str, **updates):
    job = JOBS.get(job_id)
    if not job:
        return
    job.update(updates)
    persist_job(job_id)

def recompute_summary(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return
    path = os.path.join(job["dir"], "all_results.csv")
    if not os.path.exists(path):
        return
    summary: Dict[str, int] = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            status = row.get("status", "") or "unknown"
            summary[status] = summary.get(status, 0) + 1
    job["summary"] = summary


def process_job(job_id: str, input_path: str, options: Dict):
    try:
        update_job(job_id, status="processing", phase="read", processed=0)
        with open(input_path, "rb") as f:
            raw = f.read()

        text = None
        for enc in ("utf-8", "utf-8-sig", "latin-1"):
            try:
                text = raw.decode(enc)
                break
            except Exception:
                continue
        if text is None:
            update_job(job_id, status="error", error="Unable to decode file")
            return

        reader = csv.reader(io.StringIO(text))
        try:
            first_row = next(reader)
        except StopIteration:
            update_job(job_id, status="error", error="Empty CSV")
            return

        no_header = options["no_header"]
        if no_header:
            headers = []
            data_rows = [first_row] + list(reader)
        else:
            headers = first_row
            data_rows = list(reader)

        total_rows = len(data_rows)
        update_job(job_id, total_rows=total_rows, phase="parse")

        col_idx = detect_email_column(
            headers,
            options["email_column"],
            no_header,
            len(first_row),
        )
        if col_idx is None:
            update_job(job_id, status="error", error="Email column not found. Provide a column name or number.")
            return

        use_dedupe = options["dedupe"]
        use_mx = options["check_mx"]
        use_smtp = options["check_smtp"]

        entries = []
        seen = {}

        row_index = 1 if no_header else 2
        for row in data_rows:
            emails = extract_emails_from_row(row, col_idx)
            for email in emails:
                normalized = normalize_email(email)
                entry = {
                    "input_row": row_index,
                    "email": email,
                    "normalized_email": normalized or "",
                    "status": "",
                    "reason": "",
                    "domain": "",
                    "mx_hosts": "",
                    "spf_status": "",
                    "dmarc_status": "",
                    "label": "",
                    "smtp_response": "",
                }
                if normalized is None:
                    entry["status"] = "invalid_syntax"
                    entry["reason"] = "Invalid email syntax"
                else:
                    entry["domain"] = normalized.split("@", 1)[1]
                    if use_dedupe and normalized in seen:
                        entry["status"] = "duplicate"
                        entry["reason"] = f"Duplicate of row {seen[normalized]}"
                    else:
                        seen[normalized] = row_index
                entries.append(entry)
            row_index += 1
            if row_index % 200 == 0:
                update_job(job_id, processed=min(row_index, total_rows), phase="parse")

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3
        resolver.timeout = 2
        domain_cache: Dict[str, DomainInfo] = {}
        spf_cache: Dict[str, str] = {}
        dmarc_cache: Dict[str, str] = {}

        update_job(job_id, phase="dns", processed=0, phase_total=0)
        processed_dns = 0
        dns_targets = [e for e in entries if not e["status"] and e["normalized_email"]]
        update_job(job_id, phase="dns", processed=0, phase_total=len(dns_targets))
        for entry in dns_targets:
            if entry["status"] or not entry["normalized_email"]:
                continue
            if not use_mx:
                entry["status"] = "syntax_valid"
                entry["reason"] = "Syntax OK"
                entry["label"] = classify_label(entry["status"])
                continue

            info = resolve_domain(entry["domain"], resolver, domain_cache)
            entry["status"] = info.status
            entry["reason"] = info.reason
            entry["mx_hosts"] = ";".join(info.mx_hosts)
            entry["spf_status"] = resolve_spf(entry["domain"], resolver, spf_cache)
            entry["dmarc_status"] = resolve_dmarc(entry["domain"], resolver, dmarc_cache)
            entry["label"] = classify_label(entry["status"])
            processed_dns += 1
            if processed_dns % 200 == 0:
                update_job(job_id, processed=processed_dns, phase="dns")

        # SMTP checks (optional)
        if use_smtp:
            update_job(job_id, phase="smtp", processed=0)
            smtp_targets = [e for e in entries if e["status"] == "domain_mx"]
            update_job(job_id, phase="smtp", processed=0, phase_total=len(smtp_targets))
            from concurrent.futures import ThreadPoolExecutor, as_completed

            def do_check(entry):
                time.sleep(SMTP_DELAY_SEC)
                status, reason = smtp_probe(
                    entry["normalized_email"],
                    entry["mx_hosts"].split(";") if entry["mx_hosts"] else [],
                )
                return entry, status, reason

            processed_smtp = 0
            with ThreadPoolExecutor(max_workers=MAX_SMTP_WORKERS) as pool:
                futures = [pool.submit(do_check, e) for e in smtp_targets]
                for f in as_completed(futures):
                    entry, status, reason = f.result()
                entry["status"] = status
                entry["reason"] = reason
                entry["label"] = classify_label(entry["status"])
                entry["smtp_response"] = reason
                processed_smtp += 1
                if processed_smtp % 50 == 0:
                    update_job(job_id, processed=processed_smtp, phase="smtp")

        # Write output files
        update_job(job_id, phase="write", processed=0)
        job_dir = JOBS[job_id]["dir"]
        output_path = os.path.join(job_dir, "all_results.csv")
        by_status: Dict[str, List[Dict]] = {}

        for e in entries:
            by_status.setdefault(e["status"], []).append(e)

        fieldnames = [
            "input_row",
            "email",
            "normalized_email",
            "status",
            "reason",
            "domain",
            "mx_hosts",
            "spf_status",
            "dmarc_status",
            "label",
            "smtp_response",
        ]

        def write_csv(path: str, rows: List[Dict]):
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)

        write_csv(output_path, entries)

        downloads = {"all_results": f"/download/{job_id}/all_results.csv"}
        summary = {}
        for status, rows in by_status.items():
            summary[status] = len(rows)
            safe = status.replace("/", "_")
            path = os.path.join(job_dir, f"{safe}.csv")
            write_csv(path, rows)
            downloads[status] = f"/download/{job_id}/{safe}.csv"

        update_job(
            job_id,
            status="complete",
            phase="done",
            processed=total_rows,
            downloads=downloads,
            summary=summary,
        )
    except Exception as exc:
        update_job(job_id, status="error", error=str(exc))


def smtp_batch_job(job_id: str, batch_size: int):
    try:
        job = JOBS.get(job_id)
        if not job:
            return
        update_job(job_id, status="processing", phase="smtp_batch", processed=0)
        path = os.path.join(job["dir"], "all_results.csv")
        if not os.path.exists(path):
            update_job(job_id, status="error", error="Results not found")
            return

        rows: List[Dict] = []
        targets: List[Dict] = []
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames or []
            for extra in ["spf_status", "dmarc_status", "label", "smtp_response"]:
                if extra not in fieldnames:
                    fieldnames.append(extra)
            for row in reader:
                rows.append(row)
                if len(targets) < batch_size and row.get("status") == "domain_mx":
                    targets.append(row)

        if not targets:
            update_job(job_id, status="complete", phase="done", processed=0)
            return

        update_job(job_id, phase="smtp_batch", processed=0, total_rows=len(targets))
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def do_check(entry):
            time.sleep(SMTP_DELAY_SEC)
            status, reason = smtp_probe(
                entry.get("normalized_email", ""),
                entry.get("mx_hosts", "").split(";") if entry.get("mx_hosts") else [],
            )
            return entry, status, reason

        processed = 0
        with ThreadPoolExecutor(max_workers=MAX_SMTP_WORKERS) as pool:
            futures = [pool.submit(do_check, e) for e in targets]
            for f in as_completed(futures):
                if JOBS.get(job_id, {}).get("smtp_paused"):
                    break
                entry, status, reason = f.result()
                entry["status"] = status
                entry["reason"] = reason
                entry["smtp_response"] = reason
                entry["label"] = classify_label(entry["status"])
                processed += 1
                if processed % 50 == 0:
                    update_job(job_id, processed=processed)

        # write back updated results
        tmp_path = path + ".tmp"
        with open(tmp_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        os.replace(tmp_path, path)

        recompute_summary(job_id)
        update_job(
            job_id,
            status="complete",
            phase="done",
            processed=processed,
            total_rows=len(targets),
            last_smtp_batch_at=time.time(),
        )
    except Exception as exc:
        update_job(job_id, status="error", error=str(exc))


def smtp_selected_job(job_id: str, emails: List[str]):
    try:
        job = JOBS.get(job_id)
        if not job:
            return
        update_job(job_id, status="processing", phase="smtp_selected", processed=0)
        path = os.path.join(job["dir"], "all_results.csv")
        if not os.path.exists(path):
            update_job(job_id, status="error", error="Results not found")
            return

        email_set = {e.strip().lower() for e in emails if e}
        if not email_set:
            update_job(job_id, status="complete", phase="done", processed=0)
            return

        rows: List[Dict] = []
        targets: List[Dict] = []
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames or []
            for extra in ["spf_status", "dmarc_status", "label", "smtp_response"]:
                if extra not in fieldnames:
                    fieldnames.append(extra)
            for row in reader:
                rows.append(row)
                normalized = (row.get("normalized_email") or "").lower()
                if normalized in email_set and row.get("status") == "domain_mx":
                    targets.append(row)

        update_job(job_id, phase="smtp_selected", processed=0, total_rows=len(targets))
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def do_check(entry):
            time.sleep(SMTP_DELAY_SEC)
            status, reason = smtp_probe(
                entry.get("normalized_email", ""),
                entry.get("mx_hosts", "").split(";") if entry.get("mx_hosts") else [],
            )
            return entry, status, reason

        processed = 0
        with ThreadPoolExecutor(max_workers=MAX_SMTP_WORKERS) as pool:
            futures = [pool.submit(do_check, e) for e in targets]
            for f in as_completed(futures):
                if JOBS.get(job_id, {}).get("smtp_paused"):
                    break
                entry, status, reason = f.result()
                entry["status"] = status
                entry["reason"] = reason
                entry["smtp_response"] = reason
                entry["label"] = classify_label(entry["status"])
                processed += 1
                if processed % 50 == 0:
                    update_job(job_id, processed=processed)

        tmp_path = path + ".tmp"
        with open(tmp_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        os.replace(tmp_path, path)

        recompute_summary(job_id)
        update_job(
            job_id,
            status="complete",
            phase="done",
            processed=processed,
            total_rows=len(targets),
            last_smtp_batch_at=time.time(),
        )
    except Exception as exc:
        update_job(job_id, status="error", error=str(exc))


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Ebounce Checker</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Fraunces:wght@400;600&family=DM+Sans:wght@400;500;700&display=swap');
    :root {
      --bg: #0f1115;
      --panel: #151821;
      --panel-2: #1b2030;
      --ink: #f5f7fb;
      --muted: #9aa3b2;
      --accent: #3b82f6;
      --accent-2: #22c55e;
      --border: rgba(255,255,255,0.08);
      --shadow: rgba(0,0,0,0.35);
    }
    body {
      font-family: "DM Sans", system-ui, sans-serif;
      margin: 24px;
      background:
        radial-gradient(circle at 10% 10%, #1c2540 0%, transparent 40%),
        radial-gradient(circle at 90% 20%, #2a1f40 0%, transparent 45%),
        var(--bg);
      color: var(--ink);
    }
    .wrap {
      max-width: 1200px;
      margin: 0 auto;
      background: linear-gradient(180deg, rgba(21,24,33,0.96), rgba(18,21,30,0.96));
      padding: 28px;
      border-radius: 18px;
      box-shadow: 0 18px 40px var(--shadow);
      border: 1px solid var(--border);
      backdrop-filter: blur(8px);
    }
    h1 {
      margin: 0 0 6px;
      font-size: 34px;
      letter-spacing: 0.4px;
      font-family: "Fraunces", serif;
    }
    p { color: var(--muted); margin-top: 0; }
    label {
      display: block;
      margin: 12px 0 6px;
      font-weight: 700;
      letter-spacing: 0.2px;
    }
    input[type="text"], input[type="file"], select {
      width: 100%;
      padding: 10px 12px;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: #0f1320;
      color: var(--ink);
    }
    input[type="file"] { padding: 8px; }
    input[type="text"]::placeholder { color: #6e778a; }
    .row { display: flex; gap: 16px; flex-wrap: wrap; }
    .row > div { flex: 1 1 280px; }
    .actions { margin-top: 18px; display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
    button {
      padding: 10px 18px;
      font-size: 15px;
      cursor: pointer;
      border: none;
      border-radius: 10px;
      background: linear-gradient(135deg, var(--accent), #60a5fa);
      color: #fff;
      font-weight: 600;
      letter-spacing: 0.2px;
      box-shadow: 0 10px 18px rgba(59,130,246,0.25);
    }
    #startMxBig {
      padding: 12px 22px;
      font-size: 16px;
      background: linear-gradient(135deg, #3b82f6, #22c55e);
      box-shadow: 0 12px 20px rgba(34,197,94,0.25);
    }
    button:disabled { opacity: 0.6; cursor: not-allowed; }
    .note { font-size: 13px; color: var(--muted); }
    #result { margin-top: 22px; }
    .pill {
      display: inline-block;
      padding: 6px 12px;
      border-radius: 999px;
      background: rgba(59,130,246,0.16);
      border: 1px solid rgba(59,130,246,0.35);
      margin-right: 8px;
      margin-bottom: 8px;
      font-size: 12px;
    }
    .links a { display: block; margin: 4px 0; color: #8ab4ff; }
    .progress-wrap { margin-top: 16px; }
    .progress-bar {
      height: 12px;
      background: #0f1320;
      border-radius: 999px;
      overflow: hidden;
      border: 1px solid var(--border);
    }
    .progress-bar span {
      display: block;
      height: 100%;
      width: 0%;
      background: linear-gradient(90deg, var(--accent), var(--accent-2));
      transition: width 0.2s ease;
    }
    .progress-meta { font-size: 13px; color: var(--muted); margin-top: 6px; }
    .table-wrap {
      margin-top: 18px;
      overflow: auto;
      border: 1px solid var(--border);
      border-radius: 12px;
      background: #0f1320;
    }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 10px 12px; border-bottom: 1px solid var(--border); text-align: left; }
    th { position: sticky; top: 0; background: #121726; }
    .filters { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-top: 12px; }
    .filters input, .filters select { max-width: 280px; }
    .pager { display: flex; gap: 8px; align-items: center; margin-top: 10px; }
    .pager button { background: linear-gradient(135deg, #22c55e, #16a34a); box-shadow: 0 8px 16px rgba(34,197,94,0.2); }
    .jobs { margin-top: 20px; border-top: 1px solid var(--border); padding-top: 16px; }
    .job-row {
      display: flex;
      gap: 12px;
      align-items: center;
      flex-wrap: wrap;
      margin-bottom: 8px;
      font-size: 13px;
      padding: 10px 12px;
      background: #0f1320;
      border: 1px solid var(--border);
      border-radius: 12px;
    }
    .job-row code { background: #121726; padding: 2px 6px; border-radius: 6px; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Ebounce Checker</h1>
    <p>Upload a CSV and check emails locally. First run MX (fast). Then run SMTP in small batches (slow).</p>
    <div class="note" style="margin-bottom:14px;">
      <strong>Simple steps:</strong>
      1) Click <strong>Start MX Scan</strong>.
      2) Use <strong>Only MX‑valid</strong> to filter.
      3) Select emails and run SMTP in small batches.
    </div>

    <form id="uploadForm">
      <label>CSV File</label>
      <input type="file" name="file" accept=".csv,text/csv" required />

      <div class="row">
        <div>
          <label>Email Column (optional)</label>
          <input type="text" name="email_column" placeholder="email or 1" />
          <div class="note">Leave empty to auto-detect. Use number if no header.</div>
        </div>
        <div>
          <label>Options</label>
          <div><input type="checkbox" name="dedupe" checked /> Remove duplicates</div>
          <div><input type="checkbox" name="check_mx" checked /> Check MX (fast)</div>
          <div><input type="checkbox" name="check_smtp" /> Check SMTP (slow)</div>
          <div><input type="checkbox" name="no_header" /> CSV has no header</div>
        </div>
      </div>

      <div class="actions">
        <button type="submit" id="startMxBig">Start MX Scan</button>
        <button type="button" id="presetMx">MX Only (Recommended)</button>
        <button type="button" id="inspectCsv">Detect Email Column</button>
        <span class="note" id="statusLine"></span>
      </div>
    </form>

    <div id="result"></div>
    <div class="jobs">
      <h3>Recent Jobs</h3>
      <div id="jobsList" class="note">No jobs yet.</div>
    </div>
  </div>

  <script>
    const form = document.getElementById('uploadForm');
    const result = document.getElementById('result');
    const statusLine = document.getElementById('statusLine');
    const jobsList = document.getElementById('jobsList');
    const presetMx = document.getElementById('presetMx');
    const startMxBig = document.getElementById('startMxBig');
    const inspectCsv = document.getElementById('inspectCsv');
    let pollTimer = null;
    let activeJobId = null;
    const selectedEmails = new Set();

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      result.innerHTML = '';
      statusLine.textContent = 'Uploading...';
      const data = new FormData(form);
      const res = await fetch('/process', { method: 'POST', body: data });
      if (!res.ok) {
        result.innerHTML = 'Error processing file.';
        statusLine.textContent = '';
        return;
      }
      const json = await res.json();
      if (json.error) {
        result.innerHTML = json.error;
        statusLine.textContent = '';
        return;
      }
      startPolling(json.job_id);
      await refreshJobs();
    });

    presetMx.addEventListener('click', () => {
      form.querySelector('input[name="check_mx"]').checked = true;
      form.querySelector('input[name="check_smtp"]').checked = false;
    });
    startMxBig.addEventListener('click', () => {
      form.querySelector('input[name="check_mx"]').checked = true;
      form.querySelector('input[name="check_smtp"]').checked = false;
    });
    inspectCsv.addEventListener('click', async () => {
      statusLine.textContent = 'Inspecting...';
      const data = new FormData(form);
      const res = await fetch('/inspect', { method: 'POST', body: data });
      const json = await res.json();
      if (json.error) {
        statusLine.textContent = json.error;
        return;
      }
      if (json.headers && json.headers.length) {
        const list = json.headers.map((h) => `"${h}"`).join(', ');
        statusLine.textContent = `Detected columns: ${list}`;
      } else {
        statusLine.textContent = 'No headers detected. Try using column number (1,2,3).';
      }
      if (json.guess) {
        form.querySelector('input[name="email_column"]').value = json.guess;
      }
    });

    function startPolling(jobId) {
      if (pollTimer) clearInterval(pollTimer);
      activeJobId = jobId;
      selectedEmails.clear();
      result.innerHTML = `
        <div class="progress-wrap">
          <div class="progress-bar"><span id="bar"></span></div>
          <div class="progress-meta" id="progressMeta"></div>
        </div>
        <div id="summary"></div>
        <div class="filters" id="filters" style="display:none;">
          <select id="statusFilter"></select>
          <input type="text" id="searchBox" placeholder="Search email or domain" />
          <select id="pageSize">
            <option value="50">50 rows</option>
            <option value="100" selected>100 rows</option>
            <option value="200">200 rows</option>
            <option value="500">500 rows</option>
          </select>
          <button id="refreshBtn" type="button">Refresh Preview</button>
          <button id="downloadFiltered" type="button">Download Filtered CSV</button>
          <button id="downloadRisky" type="button">Download Risky CSV</button>
          <button id="filterMxValid" type="button">Only MX‑valid</button>
          <button id="downloadSummary" type="button">Download Summary CSV</button>
          <button id="downloadMxValid" type="button">Download MX‑valid CSV</button>
          <button id="downloadSafe" type="button">Download Safe CSV</button>
          <button id="downloadRiskyLabel" type="button">Download Risky CSV</button>
          <button id="downloadInvalid" type="button">Download Invalid CSV</button>
        </div>
        <div class="filters" id="smtpControls" style="display:none;">
          <input type="number" id="smtpBatchSize" value="500" min="50" max="2000" />
          <button id="runSmtpBatch" type="button">Run SMTP on Next Batch</button>
          <button id="runSmtpSelected" type="button">Run SMTP on Selected</button>
          <button id="clearSelected" type="button">Clear Selected</button>
          <button id="selectAllPage" type="button">Select All on Page</button>
          <button id="deselectAllPage" type="button">Deselect All on Page</button>
          <button id="selectAllFiltered" type="button">Select All Filtered</button>
          <button id="pauseSmtp" type="button">Pause SMTP</button>
          <button id="resumeSmtp" type="button">Resume SMTP</button>
          <span class="note">Runs SMTP on the next 500 MX-valid emails.</span>
        </div>
        <div class="note" id="smtpLast"></div>
        <div class="pager" id="pager" style="display:none;">
          <button id="prevPage" type="button">Prev</button>
          <span class="note" id="pageLabel">Page 1</span>
          <button id="nextPage" type="button">Next</button>
        </div>
        <div class="table-wrap" id="tableWrap" style="display:none;">
          <table>
            <thead>
              <tr>
                <th>Select</th>
                <th>Row</th>
                <th>Email</th>
                <th>Normalized</th>
                <th>Status</th>
                <th>Label</th>
                <th>Reason</th>
                <th>Domain</th>
              </tr>
            </thead>
            <tbody id="previewBody"></tbody>
          </table>
        </div>
      `;

      const bar = document.getElementById('bar');
      const meta = document.getElementById('progressMeta');
      const summary = document.getElementById('summary');
      const statusFilter = document.getElementById('statusFilter');
      const searchBox = document.getElementById('searchBox');
      const pageSize = document.getElementById('pageSize');
      const refreshBtn = document.getElementById('refreshBtn');
      const downloadFiltered = document.getElementById('downloadFiltered');
      const downloadRisky = document.getElementById('downloadRisky');
      const filterMxValid = document.getElementById('filterMxValid');
      const downloadSummary = document.getElementById('downloadSummary');
      const downloadMxValid = document.getElementById('downloadMxValid');
      const downloadSafe = document.getElementById('downloadSafe');
      const downloadRiskyLabel = document.getElementById('downloadRiskyLabel');
      const downloadInvalid = document.getElementById('downloadInvalid');
      const smtpControls = document.getElementById('smtpControls');
      const smtpBatchSize = document.getElementById('smtpBatchSize');
      const runSmtpBatch = document.getElementById('runSmtpBatch');
      const runSmtpSelected = document.getElementById('runSmtpSelected');
      const clearSelected = document.getElementById('clearSelected');
      const selectAllPage = document.getElementById('selectAllPage');
      const deselectAllPage = document.getElementById('deselectAllPage');
      const selectAllFiltered = document.getElementById('selectAllFiltered');
      const pauseSmtp = document.getElementById('pauseSmtp');
      const resumeSmtp = document.getElementById('resumeSmtp');
      const smtpLast = document.getElementById('smtpLast');
      const pager = document.getElementById('pager');
      const prevPage = document.getElementById('prevPage');
      const nextPage = document.getElementById('nextPage');
      const pageLabel = document.getElementById('pageLabel');

      let page = 1;

      const loadPreview = async () => {
        const status = statusFilter.value || '';
        const query = searchBox.value || '';
        const limit = parseInt(pageSize.value, 10) || 100;
        const offset = (page - 1) * limit;
        const res = await fetch(`/preview/${jobId}?status=${encodeURIComponent(status)}&q=${encodeURIComponent(query)}&limit=${limit}&offset=${offset}`);
        const json = await res.json();
        const body = document.getElementById('previewBody');
        body.innerHTML = '';
        for (const row of json.rows || []) {
          const tr = document.createElement('tr');
          const normalized = row.normalized_email || '';
          const isChecked = selectedEmails.has(normalized);
          tr.innerHTML = `
            <td><input type="checkbox" class="rowSelect" data-email="${normalized}" ${isChecked ? 'checked' : ''} /></td>
            <td>${row.input_row}</td>
            <td>${row.email}</td>
            <td>${row.normalized_email}</td>
            <td>${row.status}</td>
            <td>${row.label || ''}</td>
            <td>${row.reason}</td>
            <td>${row.domain}</td>
          `;
          body.appendChild(tr);
        }
        body.querySelectorAll('.rowSelect').forEach((cb) => {
          cb.addEventListener('change', (e) => {
            const email = e.target.dataset.email || '';
            if (!email) return;
            if (e.target.checked) selectedEmails.add(email);
            else selectedEmails.delete(email);
          });
        });
        pageLabel.textContent = `Page ${page}`;
      };

      refreshBtn.addEventListener('click', loadPreview);
      prevPage.addEventListener('click', () => {
        if (page > 1) {
          page -= 1;
          loadPreview();
        }
      });
      nextPage.addEventListener('click', () => {
        page += 1;
        loadPreview();
      });
      pageSize.addEventListener('change', () => {
        page = 1;
        loadPreview();
      });
      searchBox.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          page = 1;
          loadPreview();
        }
      });
      statusFilter.addEventListener('change', () => {
        page = 1;
        loadPreview();
      });
      downloadFiltered.addEventListener('click', () => {
        const status = statusFilter.value || '';
        const query = searchBox.value || '';
        window.location = `/download_filtered/${jobId}?status=${encodeURIComponent(status)}&q=${encodeURIComponent(query)}`;
      });
      downloadRisky.addEventListener('click', () => {
        window.location = `/download_risky/${jobId}`;
      });
      filterMxValid.addEventListener('click', () => {
        statusFilter.value = 'domain_mx';
        page = 1;
        loadPreview();
      });
      downloadSummary.addEventListener('click', () => {
        window.location = `/download_summary/${jobId}`;
      });
      downloadMxValid.addEventListener('click', () => {
        window.location = `/download_mx_valid/${jobId}`;
      });
      downloadSafe.addEventListener('click', () => {
        window.location = `/download_label/${jobId}?label=Safe`;
      });
      downloadRiskyLabel.addEventListener('click', () => {
        window.location = `/download_label/${jobId}?label=Risky`;
      });
      downloadInvalid.addEventListener('click', () => {
        window.location = `/download_label/${jobId}?label=Invalid`;
      });

      runSmtpBatch.addEventListener('click', async () => {
        const size = parseInt(smtpBatchSize.value, 10) || 500;
        runSmtpBatch.disabled = true;
        await fetch(`/smtp_batch/${jobId}?size=${size}`, { method: 'POST' });
        runSmtpBatch.disabled = false;
        startPolling(jobId);
      });

      runSmtpSelected.addEventListener('click', async () => {
        if (selectedEmails.size === 0) return;
        runSmtpSelected.disabled = true;
        await fetch(`/smtp_selected/${jobId}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ emails: Array.from(selectedEmails) })
        });
        runSmtpSelected.disabled = false;
        startPolling(jobId);
      });

      clearSelected.addEventListener('click', () => {
        selectedEmails.clear();
        loadPreview();
      });
      selectAllPage.addEventListener('click', () => {
        document.querySelectorAll('.rowSelect').forEach((cb) => {
          cb.checked = true;
          const email = cb.dataset.email || '';
          if (email) selectedEmails.add(email);
        });
      });
      deselectAllPage.addEventListener('click', () => {
        document.querySelectorAll('.rowSelect').forEach((cb) => {
          cb.checked = false;
          const email = cb.dataset.email || '';
          if (email) selectedEmails.delete(email);
        });
      });
      selectAllFiltered.addEventListener('click', async () => {
        const status = statusFilter.value || '';
        const query = searchBox.value || '';
        const res = await fetch(`/emails_filtered/${jobId}?status=${encodeURIComponent(status)}&q=${encodeURIComponent(query)}&limit=2000`);
        const json = await res.json();
        (json.emails || []).forEach((email) => selectedEmails.add(email));
        if (json.truncated) {
          alert(`Selected first ${json.limit} emails only. Use smaller filters for more.`);
        }
        loadPreview();
      });
      pauseSmtp.addEventListener('click', async () => {
        await fetch(`/smtp_pause/${jobId}`, { method: 'POST' });
      });
      resumeSmtp.addEventListener('click', async () => {
        await fetch(`/smtp_resume/${jobId}`, { method: 'POST' });
      });

      pollTimer = setInterval(async () => {
        const res = await fetch(`/status/${jobId}`);
        const json = await res.json();
        if (json.error) {
          meta.textContent = json.error;
          statusLine.textContent = '';
          clearInterval(pollTimer);
          return;
        }
        const phaseTotal = json.phase_total || json.total_rows || 0;
        const progress = phaseTotal ? Math.min(100, Math.round((json.processed / phaseTotal) * 100)) : 0;
        bar.style.width = `${progress}%`;
        // Estimate ETA
        if (!window.__ebounceRate) {
          window.__ebounceRate = { lastTime: Date.now(), lastProcessed: 0, rate: 0 };
        }
        const rateState = window.__ebounceRate;
        const now = Date.now();
        const processed = json.processed || 0;
        const total = phaseTotal || 0;
        const deltaT = (now - rateState.lastTime) / 1000;
        const deltaP = processed - rateState.lastProcessed;
        if (deltaT > 0.5 && deltaP >= 0) {
          rateState.rate = deltaP / deltaT;
          rateState.lastTime = now;
          rateState.lastProcessed = processed;
        }
        let etaText = '';
        if (rateState.rate > 0 && total > 0) {
          const remaining = Math.max(0, total - processed);
          const seconds = Math.round(remaining / rateState.rate);
          const mins = Math.floor(seconds / 60);
          const secs = seconds % 60;
          etaText = ` | ETA: ${mins}m ${secs}s`;
        }
        meta.textContent = `Phase: ${json.phase || 'queued'} | ${processed}/${total} rows | ${progress}%${etaText}`;
        statusLine.textContent = json.status || '';
        if (json.last_smtp_batch_at) {
          const dt = new Date(json.last_smtp_batch_at * 1000);
          smtpLast.textContent = `Last SMTP batch: ${dt.toLocaleString()}`;
        }
        if (json.smtp_paused) {
          smtpLast.textContent = `${smtpLast.textContent} | SMTP paused`;
        }

        if (json.status === 'complete') {
          clearInterval(pollTimer);
          const counts = json.summary || {};
          const total = Object.values(counts).reduce((a,b) => a + b, 0) || 1;
          const pills = Object.entries(counts).map(([k,v]) => {
            const pct = Math.round((v / total) * 100);
            return `<span class="pill">${k}: ${v} (${pct}%)</span>`;
          }).join('');
          const links = Object.entries(json.downloads || {}).map(([k,v]) => `<a href="${v}">Download ${k} CSV</a>`).join('');
          summary.innerHTML = `
            <h3>Results</h3>
            <div>${pills}</div>
            <div class="links">${links}</div>
          `;

          statusFilter.innerHTML = `<option value="">All statuses</option>` + Object.keys(counts).map(k => `<option value="${k}">${k}</option>`).join('');
          document.getElementById('filters').style.display = 'flex';
          smtpControls.style.display = 'flex';
          pager.style.display = 'flex';
          document.getElementById('tableWrap').style.display = 'block';
          page = 1;
          loadPreview();
          refreshJobs();
        }
      }, 800);
    }

    async function refreshJobs() {
      const res = await fetch('/jobs');
      const json = await res.json();
      if (!json.jobs || json.jobs.length === 0) {
        jobsList.textContent = 'No jobs yet.';
        return;
      }
      jobsList.innerHTML = '';
      json.jobs.forEach(job => {
        const div = document.createElement('div');
        div.className = 'job-row';
        const loadBtn = document.createElement('button');
        loadBtn.textContent = 'Load';
        loadBtn.type = 'button';
        loadBtn.addEventListener('click', () => startPolling(job.job_id));
        div.innerHTML = `
          <code>${job.job_id}</code>
          <span>Status: ${job.status}</span>
          <span>Created: ${new Date(job.created_at * 1000).toLocaleString()}</span>
        `;
        div.appendChild(loadBtn);
        if (job.download_all) {
          const a = document.createElement('a');
          a.href = job.download_all;
          a.textContent = 'All results CSV';
          div.appendChild(a);
        }
        jobsList.appendChild(div);
      });
    }

    refreshJobs();
  </script>
</body>
</html>
"""


@app.post("/process")
async def process(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    email_column: str = Form(default=""),
    dedupe: Optional[str] = Form(default=None),
    check_mx: Optional[str] = Form(default=None),
    check_smtp: Optional[str] = Form(default=None),
    no_header: Optional[str] = Form(default=None),
):
    max_bytes = 50 * 1024 * 1024
    job_id = str(uuid.uuid4())
    job_dir = os.path.join(DATA_DIR, job_id)
    os.makedirs(job_dir, exist_ok=True)

    input_path = os.path.join(job_dir, "input.csv")
    raw = await file.read()
    if len(raw) > max_bytes:
        return JSONResponse({"error": "File too large (max 50MB)"}, status_code=400)
    with open(input_path, "wb") as f:
        f.write(raw)

    JOBS[job_id] = {
        "created_at": time.time(),
        "dir": job_dir,
        "downloads": {},
        "summary": {},
        "status": "queued",
        "phase": "queued",
        "processed": 0,
        "total_rows": 0,
        "phase_total": 0,
        "last_smtp_batch_at": None,
        "smtp_paused": False,
    }
    persist_job(job_id)

    options = {
        "email_column": email_column or None,
        "dedupe": dedupe is not None,
        "check_mx": check_mx is not None,
        "check_smtp": check_smtp is not None,
        "no_header": no_header is not None,
    }

    background_tasks.add_task(process_job, job_id, input_path, options)
    return JSONResponse({"job_id": job_id})


@app.get("/download/{job_id}/{filename}")
def download(job_id: str, filename: str):
    job = JOBS.get(job_id)
    if not job:
        return JSONResponse({"error": "Not found"}, status_code=404)
    path = os.path.join(job["dir"], filename)
    if not os.path.exists(path):
        return JSONResponse({"error": "File not found"}, status_code=404)
    return FileResponse(path, filename=filename)


@app.get("/status/{job_id}")
def status(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return JSONResponse({"error": "Not found"}, status_code=404)
    return JSONResponse(
        {
            "status": job.get("status"),
            "phase": job.get("phase"),
            "processed": job.get("processed", 0),
            "total_rows": job.get("total_rows", 0),
            "phase_total": job.get("phase_total", 0),
            "summary": job.get("summary", {}),
            "downloads": job.get("downloads", {}),
            "error": job.get("error"),
            "last_smtp_batch_at": job.get("last_smtp_batch_at"),
            "smtp_paused": job.get("smtp_paused", False),
        }
    )


@app.post("/smtp_batch/{job_id}")
def smtp_batch(job_id: str, size: int = 500, background_tasks: BackgroundTasks = None):
    job = JOBS.get(job_id)
    if not job:
        return JSONResponse({"error": "Not found"}, status_code=404)
    size = max(50, min(2000, size))
    if background_tasks is None:
        return JSONResponse({"error": "Background tasks not available"}, status_code=500)
    background_tasks.add_task(smtp_batch_job, job_id, size)
    return JSONResponse({"status": "queued", "size": size})


@app.post("/smtp_selected/{job_id}")
def smtp_selected(
    job_id: str,
    payload: Dict = Body(default={}),
    background_tasks: BackgroundTasks = None,
):
    job = JOBS.get(job_id)
    if not job:
        return JSONResponse({"error": "Not found"}, status_code=404)
    emails = payload.get("emails", []) if isinstance(payload, dict) else []
    if background_tasks is None:
        return JSONResponse({"error": "Background tasks not available"}, status_code=500)
    background_tasks.add_task(smtp_selected_job, job_id, emails)
    return JSONResponse({"status": "queued", "count": len(emails)})


@app.post("/smtp_pause/{job_id}")
def smtp_pause(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return JSONResponse({"error": "Not found"}, status_code=404)
    job["smtp_paused"] = True
    persist_job(job_id)
    return JSONResponse({"status": "paused"})


@app.post("/smtp_resume/{job_id}")
def smtp_resume(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return JSONResponse({"error": "Not found"}, status_code=404)
    job["smtp_paused"] = False
    persist_job(job_id)
    return JSONResponse({"status": "resumed"})


@app.get("/preview/{job_id}")
def preview(job_id: str, status: str = "", q: str = "", limit: int = 200, offset: int = 0):
    job = JOBS.get(job_id)
    if not job:
        return JSONResponse({"error": "Not found"}, status_code=404)
    path = os.path.join(job["dir"], "all_results.csv")
    if not os.path.exists(path):
        return JSONResponse({"rows": []})

    rows = []
    q_lower = q.lower().strip()
    skipped = 0
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if status and row.get("status") != status:
                continue
            if q_lower:
                hay = " ".join(
                    [
                        row.get("email", ""),
                        row.get("normalized_email", ""),
                        row.get("domain", ""),
                        row.get("reason", ""),
                    ]
                ).lower()
                if q_lower not in hay:
                    continue
            if skipped < offset:
                skipped += 1
                continue
            rows.append(row)
            if len(rows) >= limit:
                break

    return JSONResponse({"rows": rows})


@app.get("/jobs")
def jobs():
    items = []
    for job_id, job in sorted(JOBS.items(), key=lambda x: x[1].get("created_at", 0), reverse=True)[:20]:
        items.append(
            {
                "job_id": job_id,
                "created_at": job.get("created_at"),
                "status": job.get("status"),
                "download_all": job.get("downloads", {}).get("all_results"),
            }
        )
    return JSONResponse({"jobs": items})


@app.get("/download_risky/{job_id}")
def download_risky(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return JSONResponse({"error": "Not found"}, status_code=404)
    path = os.path.join(job["dir"], "all_results.csv")
    if not os.path.exists(path):
        return JSONResponse({"error": "File not found"}, status_code=404)

    risky_statuses = {"invalid_syntax", "domain_no_mx", "smtp_undeliverable", "smtp_unknown"}
    filename = "risky_results.csv"

    def row_iter():
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=reader.fieldnames)
            writer.writeheader()
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)
            for row in reader:
                if row.get("status") not in risky_statuses:
                    continue
                writer.writerow(row)
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)

    return StreamingResponse(
        row_iter(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/download_summary/{job_id}")
def download_summary(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return JSONResponse({"error": "Not found"}, status_code=404)
    summary = job.get("summary", {})
    total = sum(summary.values()) or 1
    filename = "summary_report.csv"

    def row_iter():
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["status", "count", "percent"])
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)
        for status, count in summary.items():
            pct = round((count / total) * 100, 2)
            writer.writerow([status, count, pct])
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

    return StreamingResponse(
        row_iter(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/download_mx_valid/{job_id}")
def download_mx_valid(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return JSONResponse({"error": "Not found"}, status_code=404)
    path = os.path.join(job["dir"], "all_results.csv")
    if not os.path.exists(path):
        return JSONResponse({"error": "File not found"}, status_code=404)

    filename = "mx_valid_results.csv"

    def row_iter():
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=reader.fieldnames)
            writer.writeheader()
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)
            for row in reader:
                if row.get("status") != "domain_mx":
                    continue
                writer.writerow(row)
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)

    return StreamingResponse(
        row_iter(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/download_label/{job_id}")
def download_label(job_id: str, label: str = ""):
    job = JOBS.get(job_id)
    if not job:
        return JSONResponse({"error": "Not found"}, status_code=404)
    path = os.path.join(job["dir"], "all_results.csv")
    if not os.path.exists(path):
        return JSONResponse({"error": "File not found"}, status_code=404)

    label = label.strip().capitalize()
    if label not in {"Safe", "Risky", "Invalid"}:
        return JSONResponse({"error": "Invalid label"}, status_code=400)

    filename = f"{label.lower()}_results.csv"

    def row_iter():
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=reader.fieldnames)
            writer.writeheader()
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)
            for row in reader:
                if (row.get("label") or "").capitalize() != label:
                    continue
                writer.writerow(row)
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)

    return StreamingResponse(
        row_iter(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/inspect")
async def inspect(file: UploadFile = File(...)):
    raw = await file.read()
    text = None
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except Exception:
            continue
    if text is None:
        return JSONResponse({"error": "Unable to decode file"}, status_code=400)

    reader = csv.reader(io.StringIO(text))
    try:
        headers = next(reader)
    except StopIteration:
        return JSONResponse({"error": "Empty CSV"}, status_code=400)

    guess = None
    for h in headers:
        if h.strip().lower() in COMMON_EMAIL_HEADERS:
            guess = h
            break

    return JSONResponse({"headers": headers, "guess": guess})


@app.get("/emails_filtered/{job_id}")
def emails_filtered(job_id: str, status: str = "", q: str = "", limit: int = 2000):
    job = JOBS.get(job_id)
    if not job:
        return JSONResponse({"error": "Not found"}, status_code=404)
    path = os.path.join(job["dir"], "all_results.csv")
    if not os.path.exists(path):
        return JSONResponse({"emails": []})

    q_lower = q.lower().strip()
    limit = max(100, min(10000, limit))
    emails = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if status and row.get("status") != status:
                continue
            if q_lower:
                hay = " ".join(
                    [
                        row.get("email", ""),
                        row.get("normalized_email", ""),
                        row.get("domain", ""),
                        row.get("reason", ""),
                    ]
                ).lower()
                if q_lower not in hay:
                    continue
            normalized = row.get("normalized_email") or ""
            if normalized:
                emails.append(normalized)
            if len(emails) >= limit:
                break

    deduped = list(dict.fromkeys(emails))
    return JSONResponse({"emails": deduped, "truncated": len(deduped) >= limit, "limit": limit})


if not TEST_MODE:
    init_db()
    load_jobs_from_db()


@app.get("/download_filtered/{job_id}")
def download_filtered(job_id: str, status: str = "", q: str = ""):
    job = JOBS.get(job_id)
    if not job:
        return JSONResponse({"error": "Not found"}, status_code=404)
    path = os.path.join(job["dir"], "all_results.csv")
    if not os.path.exists(path):
        return JSONResponse({"error": "File not found"}, status_code=404)

    q_lower = q.lower().strip()
    filename = "filtered_results.csv"

    def row_iter():
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=reader.fieldnames)
            writer.writeheader()
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)
            for row in reader:
                if status and row.get("status") != status:
                    continue
                if q_lower:
                    hay = " ".join(
                        [
                            row.get("email", ""),
                            row.get("normalized_email", ""),
                            row.get("domain", ""),
                            row.get("reason", ""),
                        ]
                    ).lower()
                    if q_lower not in hay:
                        continue
                writer.writerow(row)
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)

    return StreamingResponse(
        row_iter(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
