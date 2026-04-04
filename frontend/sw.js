const CACHE_NAME = 'void-v1';

self.addEventListener('install', event => {
  self.skipWaiting();
});

self.addEventListener('fetch', event => {
  // Pass-through for MVP
});
