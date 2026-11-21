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
  // Stop polling once the page is being left (cancel, browser result, the
  // final redirect): a poll answering "restart" would reload the page and
  // abort the navigation that carries the result to the client.
  var leaving = false;
  function leave() { leaving = true; }
  document.addEventListener("submit", leave, true);
  window.addEventListener("pagehide", leave);
  function tick() {
    if (leaving) { return; }
    if (qr && qrURL) { qr.src = qrURL + "?t=" + Date.now(); }
    var x = new XMLHttpRequest();
    x.open("GET", statusURL);
    x.setRequestHeader("Accept", "application/json");
    x.onload = function () {
      var s;
      if (leaving) { return; }
      try { s = JSON.parse(x.responseText); } catch (e) { return; }
      if (s.message && s.message !== last) { last = s.message; statusEl.textContent = s.message; }
      if (s.next) { leaving = true; window.location.assign(s.next); return; }
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
