// eidbridge ID-card login: asks the Web eID browser extension for an
// authentication token over the window.postMessage protocol that the
// web-eid.js library (MIT, Estonian Information System Authority) defines,
// and posts the token, or the extension's error code, to the bridge.
// It never moves keyboard focus.
(function () {
  "use strict";
  var form = document.getElementById("browser-form");
  if (!form) { return; }
  var challenge = form.getAttribute("data-challenge");
  var out = document.getElementById("browser-token");
  var started = false;
  window.eidbridgeBrowser = function () {
    if (started) { return; }
    started = true;
    // Extension handshake 1 s (+1 s load delay), native app 5 s, user 2 min.
    var ackTimer = window.setTimeout(function () { done({ code: "ERR_WEBEID_EXTENSION_UNAVAILABLE" }); }, 2000);
    var allTimer = window.setTimeout(function () { done({ code: "ERR_WEBEID_USER_TIMEOUT" }); }, 1000 + 5000 + 120000);
    function done(v) {
      window.clearTimeout(ackTimer);
      window.clearTimeout(allTimer);
      window.removeEventListener("message", onMessage);
      out.value = JSON.stringify(v);
      if (form.requestSubmit) { form.requestSubmit(); } else { form.submit(); }
    }
    function onMessage(ev) {
      if (ev.source !== window || !ev.data || typeof ev.data.action !== "string") { return; }
      var d = ev.data;
      if (d.action === "web-eid:authenticate-ack") { window.clearTimeout(ackTimer); return; }
      if (d.action === "web-eid:authenticate-success") {
        done({ unverifiedCertificate: d.unverifiedCertificate, unverifiedIntermediateCertificates: d.unverifiedIntermediateCertificates,
          algorithm: d.algorithm, signature: d.signature, format: d.format, appVersion: d.appVersion });
        return;
      }
      if (d.action === "web-eid:authenticate-failure") {
        var c = (d.error && d.error.code) || "ERR_WEBEID_UNKNOWN_ERROR";
        done({ code: String(c).slice(0, 64) });
      }
    }
    window.addEventListener("message", onMessage);
    window.postMessage({ action: "web-eid:authenticate", libraryVersion: "2.1.0", challengeNonce: challenge }, window.location.origin);
  };
})();
