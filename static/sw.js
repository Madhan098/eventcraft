// Service Worker for EventCraft Pro
const CACHE_NAME = 'eventcraft-pro-v3';
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
    // Skip unsupported request schemes (chrome-extension, etc.)
    try {
        const url = new URL(event.request.url);
        // Skip chrome-extension and other unsupported schemes
        if (url.protocol === 'chrome-extension:' || 
            url.protocol === 'moz-extension:' ||
            url.protocol === 'safari-extension:' ||
            url.protocol === 'chrome:' ||
            url.protocol === 'moz-extension:') {
            return; // Let browser handle these
        }
        
        // Skip all external CDN resources (jsdelivr, cdnjs, unpkg, etc.)
        // These often have CORP headers that prevent service worker caching
        if (url.origin !== self.location.origin) {
            // Skip external CDNs and let browser handle them directly
            if (url.hostname.includes('jsdelivr.net') ||
                url.hostname.includes('cdnjs.cloudflare.com') ||
                url.hostname.includes('unpkg.com') ||
                url.hostname.includes('cdn.jsdelivr.net') ||
                url.hostname.includes('lottiefiles.com') ||
                url.hostname.includes('assets5.lottiefiles.com') ||
                url.hostname.includes('fonts.googleapis.com') ||
                url.hostname.includes('fonts.gstatic.com') ||
                url.hostname.includes('api.qrserver.com')) {
                return; // Let browser handle external CDN requests
            }
        }
    } catch (e) {
        // Invalid URL, skip
        return;
    }
    
    // Only handle same-origin requests
    try {
        const url = new URL(event.request.url);
        if (url.origin !== self.location.origin) {
            return; // Skip all cross-origin requests
        }
    } catch (e) {
        return;
    }
    
    event.respondWith(
        caches.match(event.request)
            .then(response => {
                // Return cached version or fetch from network
                if (response) {
                    return response;
                }
                return fetch(event.request).catch(err => {
                    // Silently handle 403/404 errors for external resources
                    if (event.request.destination === 'image' || 
                        event.request.url.includes('.json') ||
                        event.request.url.includes('lottie')) {
                        // Return empty response for failed image/json requests
                        return new Response('', { 
                            status: 200,
                            statusText: 'OK',
                            headers: { 'Content-Type': 'text/plain' }
                        });
                    }
                    // Only log non-image/json errors
                    if (!event.request.url.includes('lottie') && 
                        !event.request.url.includes('.json')) {
                        console.warn(`Failed to fetch ${event.request.url}:`, err);
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
                        return caches.delete(cacheName).catch(err => {
                            // Ignore errors when deleting caches
                            console.warn('Failed to delete cache:', cacheName, err);
                            return null;
                        });
                    }
                })
            );
        })
    );
});
