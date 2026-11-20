// eidbridge login page: polls local flow status and refreshes the QR image
// every second. It never moves keyboard focus and announces only changes.
(function () {
  "use strict";
  var root = document.getElementById("flow");
  if (!root) { return; }
  var statusURL = root.getAttribute("data-status");
  var qrURL = root.getAttribute("data-qr");
  var statusEl = document.getElementById("status");
  var qr = document.getElementById("qr");
  var last = "";
  function tick() {
    if (qr && qrURL) { qr.src = qrURL + "?t=" + Date.now(); }
    var x = new XMLHttpRequest();
    x.open("GET", statusURL);
    x.setRequestHeader("Accept", "application/json");
    x.onload = function () {
      var s;
      try { s = JSON.parse(x.responseText); } catch (e) { return; }
      if (s.message && s.message !== last) { last = s.message; statusEl.textContent = s.message; }
      if (s.next) { window.location.assign(s.next); return; }
      if (s.state === "other_tab" || s.state === "restart") { window.location.reload(); return; }
      window.setTimeout(tick, 1000);
    };
    x.onerror = function () { window.setTimeout(tick, 2000); };
    x.send();
  }
  window.setTimeout(tick, 1000);
  var b = document.getElementById("browser-start");
  if (b && window.eidbridgeBrowser) { b.addEventListener("click", window.eidbridgeBrowser); }
})();
