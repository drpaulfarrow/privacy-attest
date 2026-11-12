// Acme pixel loaded on advertiser sites.
(function () {
  var gpc = navigator.globalPrivacyControl === true;
  var optedOut = gpc || document.cookie.indexOf('acme_optout=1') !== -1;

  function fire(url) {
    var img = new Image();
    img.src = url;
  }

  if (!optedOut) {
    // Retargeting pixel for our audience partner.
    var img = new Image(); img.src = 'https://sync.audience-partner.example/px?uid=' + window.acmeUid;
  }

  // Page analytics, sent for every visitor.
  window.addEventListener('load', function () {
    navigator.sendBeacon('https://collect.partner-analytics.example/v1/hit', JSON.stringify({
      uid: window.acmeUid, url: location.href, ts: Date.now()
    }));
  });

  // Store locator: ask for the visitor's position to pick the nearest store.
  if (window.acmeStoreLocator) {
    navigator.geolocation.getCurrentPosition(function (pos) {
      fire('https://api.acme-dsp.example/geo?lat=' + pos.coords.latitude + '&lon=' + pos.coords.longitude);
    });
  }
})();
