// Service Worker for EventCraft Pro
const CACHE_NAME = 'eventcraft-pro-v2';
const urlsToCache = [
    '/',
    '/static/css/style.css',
    '/static/js/app.js'
    // Only cache images that actually exist
    // Removed non-existent images to prevent 404 errors
];

// Install event
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => {
                console.log('Opened cache');
                // Cache files individually to handle missing files gracefully
                return Promise.allSettled(
                    urlsToCache.map(url => 
                        cache.add(url).catch(err => {
                            console.warn(`Failed to cache ${url}:`, err);
                            return null;
                        })
                    )
                );
            })
    );
});

// Fetch event
self.addEventListener('fetch', event => {
    event.respondWith(
        caches.match(event.request)
            .then(response => {
                // Return cached version or fetch from network
                if (response) {
                    return response;
                }
                return fetch(event.request).catch(err => {
                    console.warn(`Failed to fetch ${event.request.url}:`, err);
                    // Return a basic response for failed requests
                    if (event.request.destination === 'image') {
                        return new Response('', { status: 404 });
                    }
                    throw err;
                });
            }
        )
    );
});

// Activate event
self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames.map(cacheName => {
                    if (cacheName !== CACHE_NAME) {
                        console.log('Deleting old cache:', cacheName);
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
});
