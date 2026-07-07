// background.js - minimal service worker
// Keeps the extension ready; no external communication.

self.addEventListener('install', (evt)=>{
  // Service worker installed
  self.skipWaiting();
});

self.addEventListener('activate', (evt)=>{
  // Ready
  clients.claim();
});

// optional: handle messages from popup
self.addEventListener('message', (e)=>{
  // no-op for now
});
