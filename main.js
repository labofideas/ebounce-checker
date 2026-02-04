const { app, BrowserWindow, dialog } = require('electron');
const { autoUpdater } = require('electron-updater');
const { ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const http = require('http');
const net = require('net');

let backendProcess = null;

function logPath() {
  return path.join(app.getPath('userData'), 'ebounce.log');
}

function logLine(line) {
  fs.appendFileSync(logPath(), `[${new Date().toISOString()}] ${line}\n`);
}

async function findOpenPort(start = 8000) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.unref();
    server.on('error', () => resolve(start + 1));
    server.listen({ port: start, host: '127.0.0.1' }, () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}

function run(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: 'pipe', ...opts });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => (out += d.toString()));
    child.stderr.on('data', (d) => (err += d.toString()));
    child.on('close', (code) => {
      if (code === 0) return resolve({ out, err });
      reject(new Error(err || out || `Command failed: ${cmd}`));
    });
  });
}

async function ensureVenv(backendDir, venvDir) {
  if (!fs.existsSync(venvDir)) {
    logLine('Creating venv...');
    await run('python3', ['-m', 'venv', venvDir]);
  }
  const pipPath = path.join(venvDir, 'bin', 'pip');
  const reqPath = path.join(backendDir, 'requirements.txt');
  logLine('Installing backend requirements...');
  await run(pipPath, ['install', '-r', reqPath]);
}

async function waitForServer(port, timeoutMs = 20000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await new Promise((resolve, reject) => {
        const req = http.get({ hostname: '127.0.0.1', port, path: '/' }, (res) => {
          res.resume();
          resolve();
        });
        req.on('error', reject);
      });
      return true;
    } catch (e) {
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  return false;
}

function createLoadingWindow() {
  const win = new BrowserWindow({
    width: 520,
    height: 320,
    resizable: false,
    title: 'Ebounce Checker',
    backgroundColor: '#0f1115',
    webPreferences: {
      contextIsolation: true
    }
  });
  win.loadURL('data:text/html,' + encodeURIComponent(`
    <html><body style="margin:0;display:flex;align-items:center;justify-content:center;background:#0f1115;color:#f5f7fb;font-family:DM Sans,Arial;">
      <div style="text-align:center;">
        <div style="font-size:20px;margin-bottom:6px;">Ebounce Checker</div>
        <div style="font-size:13px;color:#9aa3b2;">Starting local engine…</div>
      </div>
    </body></html>
  `));
  return win;
}

async function startBackend() {
  const baseDir = app.isPackaged ? process.resourcesPath : __dirname;
  const backendDir = path.join(baseDir, 'backend');
  const venvDir = path.join(app.getPath('userData'), 'pyenv');
  const pythonPath = path.join(venvDir, 'bin', 'python');

  await ensureVenv(backendDir, venvDir);
  const port = await findOpenPort(8000);
  logLine(`Starting backend on port ${port}`);

  backendProcess = spawn(
    pythonPath,
    ['-m', 'uvicorn', 'app:app', '--host', '127.0.0.1', '--port', String(port)],
    { cwd: backendDir, stdio: 'pipe' }
  );

  backendProcess.stdout.on('data', (d) => logLine(d.toString().trim()));
  backendProcess.stderr.on('data', (d) => logLine(d.toString().trim()));
  backendProcess.on('close', (code) => logLine(`Backend exited: ${code}`));

  const ready = await waitForServer(port);
  if (!ready) throw new Error('Backend failed to start');
  return port;
}

app.whenReady().then(async () => {
  const loading = createLoadingWindow();
  try {
    const port = await startBackend();
    const win = new BrowserWindow({
      width: 1200,
      height: 800,
      title: 'Ebounce Checker',
      backgroundColor: '#0f1115',
      webPreferences: {
        contextIsolation: true,
        preload: path.join(__dirname, 'preload.js')
      }
    });
    win.loadURL(`http://127.0.0.1:${port}`);
    loading.close();
    autoUpdater.checkForUpdatesAndNotify().catch((err) => {
      logLine(`Auto-update error: ${err.message}`);
    });
    ipcMain.handle('check-for-updates', async () => {
      try {
        await autoUpdater.checkForUpdatesAndNotify();
        return { ok: true };
      } catch (err) {
        logLine(`Manual update check error: ${err.message}`);
        return { ok: false, error: err.message };
      }
    });
  } catch (err) {
    loading.close();
    dialog.showErrorBox('Ebounce Checker', `Failed to start backend.\n\n${err.message}\n\nSee log: ${logPath()}`);
  }
});

app.on('before-quit', () => {
  if (backendProcess) {
    backendProcess.kill();
    backendProcess = null;
  }
});
