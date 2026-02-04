const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('ebounce', {
  checkUpdates: async () => {
    return await ipcRenderer.invoke('check-for-updates');
  }
});
