const { app, BrowserWindow, Menu, shell } = require("electron");
const path = require("path");

const APP_URL = process.env.ELECTRON_APP_URL || "https://your-app.onrender.com";

function createMainWindow() {
  const mainWindow = new BrowserWindow({
    width: 1280,
    height: 840,
    minWidth: 960,
    minHeight: 640,
    backgroundColor: "#f3f0e8",
    autoHideMenuBar: true,
    title: "Simple Notepad",
    webPreferences: {
      contextIsolation: true,
      sandbox: true,
    },
  });

  mainWindow.loadURL(APP_URL);

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });
}

app.whenReady().then(() => {
  Menu.setApplicationMenu(null);
  createMainWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createMainWindow();
    }
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});
