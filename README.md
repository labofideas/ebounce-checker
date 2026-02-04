# Ebounce Checker (Electron)

This is a desktop app wrapper for the local FastAPI email checker.

## Run (dev)
```bash
cd "/Users/shashank/Desktop/Ebounce Checker App"
npm install
npm start
```

On first run, the app will:
- Create a Python venv in your user data folder
- Install backend requirements
- Start the FastAPI server on a local port

Logs: `~/Library/Application Support/Ebounce Checker/ebounce.log`

## Notes
- Requires system `python3` available in PATH.
- The first run needs internet to install Python packages.
