package oidcportal

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

// The lines this deployment puts in magpie's page are scripts in it: one
// syntax error and none of a person's console runs (a browser says
// "Unexpected token" and draws magpie's page for the whole deployment).
// node's parser is a way to ask, but only a browser's is the last word.
func TestThePagesOwnScriptsParse(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	for name, src := range map[string][]byte{
		"a person's": personScript(Identity{Email: "bob@example.com", Subject: "bob"}, User{KeyID: "k1"}),
		// an admin's is a <script> element of its own, its code between them
		"an admin's": scriptCode(adminPre(Identity{Email: "boss@example.com"})),
	} {
		cmd := exec.Command(node, "-e", "try{new Function(require('fs').readFileSync(0,'utf8'))}catch(e){console.error(e.message);process.exit(1)}")
		// a person's script is an IIFE of its own; an admin's is the code
		// between its <script> tags, wrapped as the page wraps it
		in := src
		if name != "a person's" {
			in = append(append([]byte("(function(){\n"), src...), []byte("\n})();")...)
		}
		cmd.Stdin = bytes.NewReader(in)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s script does not parse: %s\n%s", name, out, src)
		}
	}
}

// scriptCode is the code of a <script> element: what is between its tags.
func scriptCode(el []byte) []byte {
	s := string(el)
	i := strings.Index(s, ">")
	j := strings.LastIndex(s, "</script>")
	if i < 0 || j < i {
		return el
	}
	return []byte(s[i+1 : j])
}

// The page a portal's own page is drawn in (magpiepage.go) has its script
// too: one syntax error and the page is blank.
func TestTheFramedPagesScriptParses(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	cmd := exec.Command(node, "-e", "try{new Function(require('fs').readFileSync(0,'utf8'))}catch(e){console.error(e.message);process.exit(1)}")
	cmd.Stdin = strings.NewReader(pageScript)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the framed pages' script does not parse: %s\n%s", out, pageScript)
	}
}

// The framed pages' script, run as their page runs it, with magpie's page
// absent: it draws what a page says it draws, in magpie's elements, and
// says nothing of a page the frame does not have. node is the smallest page
// around it (see runnerJS).
func TestTheFramedPagesScriptRuns(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	cmd := exec.Command(node, "-e", runnerJS)
	cmd.Stdin = strings.NewReader(pageScript)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the framed pages' script: %v\n%s", err, out)
	}
}

// runnerJS is node's page for pagejs.go: elements are records, t() and
// magpie's strings do nothing, and after its script runs, the sidebar's
// pages and the view's blocks are what the page's data says.
const runnerJS = `
const src = require("fs").readFileSync(0, "utf8");
const mk = (tag) => ({ tag, children: [], textContent: "", style: {}, dataset: {},
  setAttribute() {}, removeAttribute() {}, appendChild(c) { this.children.push(c); return c },
  replaceChildren() { this.children = []; }, querySelector: () => null,
  classList: { add() {}, toggle() {} }, addEventListener() {}, set innerHTML(v) {} });
const els = {};
const get = (k) => (els[k] ??= mk(k));
const data = { title: "门户管理", crumb: "网站门户控制管理", person: "boss@example.com", open: "admin",
  pages: [{ key: "admin", label: "门户管理", href: "/admin", view: true }, { key: "logout", label: "退出登录", href: "/logout" }],
  notice: "已保存",
  blocks: [
    { head: "人员", stats: [{ value: "2", label: "人" }], table: { head: ["人员", ""], rows: [["bob", "/admin/user?sub=bob"]], bad: [false] } },
    { form: { post: "/admin", get: true, fields: [{ name: "status", label: "状态", kind: "select", options: ["", "active"] }], acts: [{ label: "筛选", submit: true }] } },
    { head: "用量", form: { post: "/admin/user?sub=bob&", tabs: [{ label: "今天", kind: "seg-on" }, { label: "全部", href: "/admin/user?sub=bob&period=all" }] } },
    { rows: [{ name: "状态", tag: "在用", tagOn: "good", acts: [{ label: "停用", kind: "danger", post: "/admin/disable", sub: "bob" }] }] },
  ] };
globalThis.t = (s) => s;
globalThis.magpie = { strings() {} };
globalThis.document = { readyState: "complete", getElementById: (id) => (id === "oidc-page" ? { textContent: JSON.stringify(data) } : get(id)),
  createElement: mk, createElementNS: mk, querySelector: get, querySelectorAll: () => [], title: "", addEventListener() {} };
globalThis.window = { location: { assign() {}, search: "" }, confirm: () => false, addEventListener() {} };
globalThis.location = window.location;
new Function(src)();
const tags = (n) => (n ? n.children.map((c) => c.tag).join(",") : "");
if (tags(els["#nav"]) !== "a,a") throw new Error("nav: " + tags(els["#nav"]));
if (els["#pageTitle"].textContent !== "门户管理") throw new Error("title: " + els["#pageTitle"].textContent);
if (!tags(els["#view-oidc"]).includes("div")) throw new Error("blocks: " + tags(els["#view-oidc"]));
`

// A person's console is magpie's page again, its #nav moved into the
// sidebar (layoutNav) as it is: mark() keeps that node where the page finds
// its buttons, leaves 我的密钥 and 用量 in it, and takes out the page's
// own (and the groups' lines), so the page's views are not a person's.
// node's elements are the smallest the page needs (personRunner).
func TestAPersonsSidebarIsTheirTwoPages(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	cmd := exec.Command(node, "-e", personRunner)
	cmd.Stdin = bytes.NewReader(personScript(Identity{Email: "bob@example.com", Subject: "bob"}, User{KeyID: "k1"}))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("a person's sidebar: %v\n%s", err, out)
	}
}

// personRunner is node's page for consolepage.go's personScript: magpie's
// sidebar with #nav already in it, holding the page's own buttons and its
// groups' lines; after the script, the nav holds the two buttons, 我的密钥
// and 用量, and neither the page's views nor its group lines — the nav is
// what the page lays its buttons out in (layoutNav), so the sidebar keeps it
const personRunner = `
const src = require("fs").readFileSync(0, "utf8");
let id = 0;
const mk = (tag) => {
  const n = { tag, id: ++id, nodeType: 1, children: [], parentNode: null, textContent: "", style: {}, dataset: {},
    classList: { set: new Set(), add(c) { this.set.add(c) }, remove(c) { this.set.delete(c) },
      contains(c) { return this.set.has(c) }, toggle(c, on) { if (on === undefined) on = !this.set.has(c); on ? this.set.add(c) : this.set.delete(c) } },
    get className() { return [...this.classList.set].join(" ") }, set className(v) { this.classList.set = new Set(String(v).split(/\s+/).filter(Boolean)) },
    appendChild(c) { if (c.parentNode) c.remove(); this.children.push(c); c.parentNode = this; return c },
    insertBefore(c, b) { if (c.parentNode) c.remove(); const i = b ? this.children.indexOf(b) : -1; if (i < 0) this.children.push(c); else this.children.splice(i, 0, c); c.parentNode = this; return c },
    removeChild(c) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); c.parentNode = null; return c },
    remove() { this.parentNode && this.parentNode.removeChild(this) },
    replaceChildren(...cs) { this.children.slice().forEach((c) => this.removeChild(c)); cs.forEach((c) => this.appendChild(c)) },
    setAttribute(k, v) { this[k] = String(v) }, removeAttribute(k) { delete this[k] },
    querySelector(sel) { return this.querySelectorAll(sel)[0] || null }, querySelectorAll(sel) {
      const out = [];
      const want = sel.split(",").map((s) => s.trim());
      const hits = (c, w) => {
        if (c.tag !== "button" || !w.startsWith("button[data-view")) return false;
        if (w === "button[data-view]") return !!c.dataset.view;
        const m = w.match(/^button\[data-view="([^"]+)"\]$/);
        return !!m && c.dataset.view === m[1];
      };
      const cls = (n) => [...n.classList.set].join(" ");
      const walk = (n) => n.children.forEach((c) => { if (want.some((w) => hits(c, w) || (w.startsWith(".") && cls(c).split(/\s+/).includes(w.slice(1))))) out.push(c); walk(c) });
      walk(this); return out }, childNodes() { return this.children }, addEventListener() {}, hidden: false, contains(o) { for (let n = o; n; n = n.parentNode) if (n === this) return true; return false }, isSameNode(o) { return o === this } };
  Object.defineProperty(n, "childNodes", { get() { return n.children } });
  return n;
};
const body = mk("body");
const side = body.appendChild(mk("div"));
side.className = "side-scroll";
const nav = side.appendChild(mk("nav"));
const gl = nav.appendChild(mk("span")); gl.className = "nav-gl";
const btn = (v) => { const b = mk("button"); b.dataset.view = v; const s = b.appendChild(mk("span")); s.textContent = v; nav.appendChild(b); return b };
const viewUsage = body.appendChild(mk("main")); viewUsage.id = "view-usage"; viewUsage.innerText = "Usage";
const pageTitle = body.appendChild(mk("div")); pageTitle.id = "pageTitle"; pageTitle.textContent = "我的密钥";
const b = (v) => { const x = mk("button"); x.dataset.view = v; const s = x.appendChild(mk("span")); s.textContent = v; return x };
const pageViews = ["agents", "usage", "gateway", "plugins"].map(b);
pageViews.forEach((v) => nav.appendChild(v));
const usage = pageViews[1];
const foot = body.appendChild(mk("div")); foot.className = "side-foot";
const els = { "#nav": nav, ".side-scroll": side, ".side-foot": foot, "#view-usage": viewUsage, "#pageTitle": pageTitle };
globalThis.document = { readyState: "complete", getElementById: () => null, querySelector: (s) => els[s] || null,
  createElement: mk, createElementNS: mk, body, title: "", addEventListener() {} };
globalThis.t = (s) => s;
globalThis.show = () => {};
globalThis.I18N = { zh: {} };
globalThis.location = { pathname: "/", search: "" };
globalThis.history = { replaceState() {} };
globalThis.MutationObserver = class { observe() {} };
globalThis.setInterval = () => 0;
globalThis.setTimeout = () => 0;
globalThis.window = { addEventListener() {}, oidcPerson: { email: "bob@example.com" } };
globalThis.window.magpie = globalThis.magpie = { plugin(id, setup) { setup({ slots: { add() {} } }) }, strings() {}, page: () => undefined, pages: () => ["mine", "oidc-usage"] };
new Function(src)();
const navBtns = nav.children.filter((c) => c.tag === "button" && c.dataset.view);
if (navBtns.map((b) => b.dataset.view).join(",") !== "usage,mine")
  throw new Error("the person's nav: " + JSON.stringify(navBtns.map((b) => b.dataset.view)));
if (!side.children.includes(nav)) throw new Error("the page's #nav left the sidebar");
if (nav.children.some((c) => c.className === "nav-gl")) throw new Error("a group line is left in the nav");
if (nav.children.filter((c) => c.tag === "button" && c.dataset.view && c.dataset.view !== "usage" && c.dataset.view !== "mine").length)
  throw new Error("the page's own views are left in the nav");
if (foot.children.length === 0) throw new Error("the person is not at the sidebar's foot");
`

// An admin's script takes the page's nav down to the role's pages: the
// Work group (agents, sessions, library) is out for every admin, and the
// document's class says which role reads it.
func TestAnAdminsNavMatchesTheirRole(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	cmd := exec.Command(node, "-e", adminRunner)
	cmd.Stdin = strings.NewReader(string(scriptCode(adminPre(Identity{
		Email: "boss@example.com", Groups: []string{RoleOperator},
	}))))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("an operator's nav: %v\n%s", err, out)
	}
}

// The page's first script (consoleboot.go's roleScript) says whose console
// it is: the document's class is the person's role, which console.css prunes
// by. node runs it as the page does — after the page has loaded, its timer
// fired at once — for a super admin, an operator and a person.
func TestTheRoleClassIsThePersons(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	cmd := exec.Command(node, "-e", roleRunner)
	cmd.Stdin = strings.NewReader(roleScript)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the role class: %v\n%s", err, out)
	}
}

// roleRunner is node's page for roleScript: a document that has loaded, a
// timer that fires at once, and one pass per person — the class each one's
// page ends with.
const roleRunner = `
const src = require("fs").readFileSync(0, "utf8");
const pass = (who) => {
  const ready = [];
  const html = { className: "page" };
  globalThis.document = { documentElement: html, addEventListener(t, f) { if (t === "DOMContentLoaded") ready.push(f) } };
  globalThis.setTimeout = (f) => { f(); return 0 };
  globalThis.window = { oidcPerson: who };
  new Function(src)();
  if (!ready.length) throw new Error("the role script waits on nothing: " + JSON.stringify(who));
  ready.forEach((f) => f());
  return html.className.split(" ");
};
const want = (who, cls) => { const c = pass(who); if (!c.includes(cls)) throw new Error(JSON.stringify(who) + ": " + JSON.stringify(c)); };
want({ admin: true, super: true }, "oidc-super");
want({ admin: true, super: false }, "oidc-operator");
want({}, "oidc-person");
`

// adminRunner is node's page for consolepage.go's adminPre: magpie's
// sidebar with #nav holding every view's button and the page opened on
// Agents; and the page's first script (consoleboot.go's roleScript), run
// afterwards, as /boot.js runs it before the page's own. After them, the
// Work views are out of the nav, the console's stay, the document says
// whose console it is, and the admin is on Providers, not Agents.
// adminRunner is node's page for consolepage.go's adminPre: magpie's
// sidebar with #nav holding every view's button; and the page's first
// script (consoleboot.go's roleScript), run afterwards, as /boot.js runs it
// before the page's own. After them, the Work views are out of the nav, the
// console's stay, and the document says whose console it is.
const adminRunner = `
const src = require("fs").readFileSync(0, "utf8");
let id = 0;
const mk = (tag) => {
  const n = { tag, id: ++id, nodeType: 1, children: [], parentNode: null, textContent: "", style: {}, dataset: {},
    classList: { set: new Set(), add(c) { this.set.add(c) }, remove(c) { this.set.delete(c) },
      contains(c) { return this.set.has(c) }, toggle(c, on) { if (on === undefined) on = !this.set.has(c); on ? this.set.add(c) : this.set.delete(c) } },
    get className() { return [...this.classList.set].join(" ") }, set className(v) { this.classList.set = new Set(String(v).split(/\s+/).filter(Boolean)) },
    appendChild(c) { if (c.parentNode) c.remove(); this.children.push(c); c.parentNode = this; return c },
    removeChild(c) { const i = this.children.indexOf(c); if (i >= 0) this.children.splice(i, 1); c.parentNode = null; return c },
    remove() { this.parentNode && this.parentNode.removeChild(this) },
    setAttribute(k, v) { this[k] = String(v) }, removeAttribute(k) { delete this[k] },
    querySelector(sel) { return this.querySelectorAll(sel)[0] || null }, querySelectorAll(sel) {
      const out = [];
      const want = sel.split(",").map((s) => s.trim());
      const hits = (c, w) => {
        if (c.tag !== "button" || !w.startsWith("button[data-view")) return false;
        if (w === "button[data-view]") return !!c.dataset.view;
        const m = w.match(/^button\[data-view="([^"]+)"\]$/);
        return !!m && c.dataset.view === m[1];
      };
      const walk = (n) => n.children.forEach((c) => { if (want.some((w) => hits(c, w))) out.push(c); walk(c) });
      walk(this); return out }, addEventListener() {}, hidden: false,
    contains(o) { for (let n = o; n; n = n.parentNode) if (n === this) return true; return false } };
  Object.defineProperty(n, "childNodes", { get() { return n.children } });
  return n;
};
const body = mk("body");
const side = body.appendChild(mk("div"));
side.className = "side-scroll";
const nav = side.appendChild(mk("nav"));
nav.id = "nav";
const views = ["agents", "sessions", "library", "providers", "routing", "gateway", "usage", "masking", "plugins"];
// the page's views: Agents drawn and its button the one on, the rest hidden
// (the page's show draws one); its Work views in the nav, pruned or not
const pageViews = {};
views.forEach((v) => { const b = nav.appendChild(mk("button")); b.dataset.view = v;
  if (v === "agents") b.classList.add("on");
  const m = body.appendChild(mk("main")); m.id = "view-" + v; m.className = "view"; m.hidden = v !== "agents"; pageViews[v] = m });
const foot = body.appendChild(mk("div")); foot.className = "side-foot";
const els = { "#nav": nav, ".side-scroll": side, ".side-foot": foot };
for (const v of views) els["#view-" + v] = pageViews[v];
const doc = { readyState: "complete", documentElement: mk("html"), ready: [], getElementById: (id) => els["#" + id] || null,
  querySelector: (s) => els[s] || null, querySelectorAll: (sel) => body.querySelectorAll(sel), createElement: mk, body, title: "",
  addEventListener(t, f) { if (t === "DOMContentLoaded") this.ready.push(f) } };
globalThis.document = doc;
globalThis.t = (s) => s;
// the page's own show: draws the view's page, and makes its button the one
// on (the page's own Agents if it has no page of that name), and says which
const shown = [];
globalThis.show = (v) => { const at = views.includes(v) ? v : "agents"; shown.push(at);
  views.forEach((w) => { pageViews[w].hidden = w !== at; const b = nav.querySelector('button[data-view="' + w + '"]'); if (b) b.classList.toggle("on", w === at) });
  return true; };
globalThis.I18N = { zh: {} };
globalThis.location = { pathname: "/", search: "" };
const timers = [];
globalThis.MutationObserver = class { observe() {} };
globalThis.setInterval = () => 0;
globalThis.setTimeout = (f) => { timers.push(f); return 0 };
globalThis.window = { addEventListener() {} };
globalThis.window.oidcPerson = { email: "boss@example.com", admin: true, super: false };
// the document says whose console it is before the page draws it: the
// class stands for the role until consoleboot.go's roleScript writes it
const load = doc.ready.slice();
doc.ready = [];
doc.documentElement.className = "oidc-operator";
// the page calls its show for the view it opens, where this script does,
// on the same turn: after the script's first look, before its next turn
const turn = timers.splice(0);
new Function(src)();
if (timers.length === 0) throw new Error("the page draws no view of its own?");
show("agents");
turn.forEach((f) => f());
doc.ready.push(...load);
doc.ready.forEach((f) => f());
timers.splice(0).forEach((f) => f());
const left = nav.children.filter((c) => c.tag === "button" && c.dataset.view).map((b) => b.dataset.view).join(",");
if (left !== "providers,routing,gateway,usage,masking,plugins") throw new Error("an operator's nav: " + left);
const roles = doc.documentElement.className.split(" ").filter((c) => c.startsWith("oidc-") && c !== "oidc-pruned");
if (roles.join(",") !== "oidc-operator") throw new Error("the document's class: " + JSON.stringify(doc.documentElement.className));
// the page opened its Agents, which an admin has not: the admin was steered
// to Providers, its page drawn, its button the one on
if (!pageViews.agents.hidden || pageViews.providers.hidden) throw new Error("the page's Agents is still drawn");
if (!nav.querySelector('button[data-view="providers"]').classList.contains("on")) throw new Error("Providers is not the view on");
if (shown[shown.length - 1] !== "providers") throw new Error("the admin was left on the page's: show(" + shown.join(",") + ")");
// the page's own call after it, on the same turn, is the last word: the
// steer is not run over it again
show("routing");
timers.splice(0).forEach((f) => f());
if (shown.slice(-1).join() !== "routing") throw new Error("the page's own view, steered over: show(" + shown.join(",") + ")");
show("gone");
if (shown.slice(-1).join() !== "agents") throw new Error("the page's own Agents, steered over: show(" + shown.join(",") + ")");
const before = shown.length;
timers.splice(0).forEach((f) => f());
if (shown.length !== before) throw new Error("the steer runs on: show(" + shown.join(",") + ")");
`
