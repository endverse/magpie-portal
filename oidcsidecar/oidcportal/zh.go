package oidcportal

import "encoding/json"

// zhConsole is magpie's own page in Chinese. magpie web translates what
// app.js and the plugin pages draw; these are the strings its Gateway page
// and its settings draw as plain HTML (plugins/gateway/keys.js and
// settings.js), which no translation reaches. The console proxy adds
// console-zh.js to the page it serves, and this is where the lines this
// deployment can see are answered.
//
// Keyed by the English as magpie writes it; a page this build does not know
// keeps its English, so a newer magpie reads no worse than before.
var zhConsole = map[string]string{
	// the Gateway page, only where magpie's own Chinese does not reach
	"LAN sharing":                "局域网共享",
	"Connect":                    "接入",
	"LAN":                        "局域网",
	"Routes":                     "路由",
	"LAN access":                 "局域网访问",
	"The gateway is not running": "网关未运行",
}

// zhConsoleJS is the script the console proxy adds to magpie's page: it
// answers zhConsole's English lines in Chinese, and hands /me the key, so
// an admin or super admin sees their own key's page from the portal's
// sign-in alone. The app draws the page again as it changes; the observer
// follows.
const zhConsoleJS = `(function () {
  var zh = %s;
  var me = {origin: %q, id: %q, name: %q, key: %q};
  function onKeyPage() {
    return new URL(me.origin).port === location.port &&
      (location.pathname === "/me" || location.pathname === "/me/");
  }
  if (onKeyPage()) {
    // the page reads its key from this tab: the holder it is for
    try { sessionStorage.setItem("magpie-key", me.key); } catch (e) {}
    try { sessionStorage.setItem("magpie-me-key", me.key); } catch (e) {}
    // its language comes from the browser; here it is Chinese
    try { Object.defineProperty(navigator, "languages", {get: function () { return ["zh-CN"]; }}); } catch (e) {}
    try { Object.defineProperty(navigator, "language", {get: function () { return "zh-CN"; }}); } catch (e) {}
  }
  // the Gateway page lists every key: the page its holder opens is /me,
  // where only their own is
  function swapHolders() {
    if (new URL(me.origin).port !== location.port) return;
    var b = document.getElementById("gwKeyPageLink");
    if (!b || b.dataset.own) return;
    var as = b.querySelectorAll("a");
    if (!as.length) return;
    b.dataset.own = "1";
    for (var i = 0; i < as.length; i++) {
      as[i].href = "//" + location.host + "/me";
      as[i].textContent = "//" + location.host + "/me";
    }
  }
  // the key page's own Rotate asks the gateway with a key the page shows
  // only masked; here the portal rotates this holder's key instead
  function hookRotate() {
    if (!onKeyPage()) return;
    document.addEventListener("click", function (e) {
      var b = e.target && e.target.closest && e.target.closest("button");
      if (!b || !/^(Rotate key|轮换密钥)$/.test(b.textContent.trim())) return;
      e.preventDefault();
      e.stopPropagation();
      b.disabled = true;
      fetch("/me/rotate", {method: "POST", credentials: "include", cache: "no-store"})
        .then(function (x) { if (!x.ok) throw 0; return x.json(); })
        .then(function (d) {
          me.key = d.key;
          try { sessionStorage.setItem("magpie-key", me.key); } catch (x) {}
          setTimeout(function () { location.reload(); }, 200);
        })
        .catch(function () { b.disabled = false; });
    }, true);
  }
  function each(root, fn) {
    if (root.nodeType === 3) { fn(root); return; }
    if (root.nodeType !== 1 || /^(SCRIPT|STYLE|CODE|PRE|TEXTAREA|INPUT|svg)$/.test(root.tagName)) return;
    var w = document.createTreeWalker(root, 4);
    for (var n; (n = w.nextNode()); ) fn(n);
  }
  function swap(n) {
    var s = n.nodeValue, t = s.trim();
    if (!t || !zh[t]) return;
    n.nodeValue = s.replace(t, zh[t]);
  }
  function run() {
    var cn = /^zh/i.test(document.documentElement.lang || navigator.language || "");
    if (cn) {
      each(document.body, swap);
      var es = document.querySelectorAll("[aria-label],[title],[placeholder]");
      for (var i = 0; i < es.length; i++) {
        ["aria-label", "title", "placeholder"].forEach(function (a) {
          var v = es[i].getAttribute(a);
          if (v && zh[v.trim()]) es[i].setAttribute(a, zh[v.trim()]);
        });
      }
    }
    swapHolders();
  }
  function watch() {
    var t;
    new MutationObserver(function () { clearTimeout(t); t = setTimeout(run, 120); })
      .observe(document.body, {childList: true, subtree: true, characterData: true});
    setInterval(run, 2000);
  }
  if (document.body) { run(); watch(); } else document.addEventListener("DOMContentLoaded", function () { run(); watch(); });
  hookRotate();
})();
`

// objJSON writes v as a JavaScript object literal: %s, not %q, so a string
// is quoted and the map is a plain object.
func objJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("null")
	}
	return b
}
