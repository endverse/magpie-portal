package oidcportal

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The console's page is magpie's own (internal/gui/assets), served as it
// is: index.html and every script and stylesheet it names, with the hash of
// its content in each address, as magpie serves them. Nothing in the page
// is rewritten but the addresses' version (the portal serves some of them
// from its embedding of the same files); what is added is what goes before
// its last script, start.js: whose console this is (oidcPerson), and an
// ordinary person's own sidebar and pages (personScript).
const (
	consolePageTTL = 15 * time.Minute
	consolePageMax = 1 << 20
)

// pageFile is magpie's own (internal/gui/api.go): the scripts and
// stylesheets the page names itself, with the version magpie gives them.
var pageFile = regexp.MustCompile(`(src|href)="([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.(?:js|css))(?:\?v=[0-9a-f]{12})?"`)

// consolePage is the page once, with its versioned addresses and its files.
var consolePage struct {
	at    time.Time
	page  []byte
	files map[string]bool
}

// forced reads the page anew every time (the tests' magpie answers a page
// of its own).
var forced bool

func (f *consoleFetch) loadPage(r *http.Request) ([]byte, map[string]bool, error) {
	if !forced && !consolePage.at.IsZero() && time.Since(consolePage.at) < consolePageTTL {
		return consolePage.page, consolePage.files, nil
	}
	raw, err := f.raw(r, "/")
	if err != nil {
		return nil, nil, err
	}
	page, files := versionedConsolePage(raw)
	if !forced {
		consolePage.at, consolePage.page, consolePage.files = time.Now(), page, files
	}
	return page, files, nil
}

// raw fetches a console path as magpie serves it.
func (f *consoleFetch) raw(r *http.Request, p string) ([]byte, error) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet,
		f.upstream.Scheme+"://"+f.upstream.Host+p, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	// magpie web keeps its pages behind its key's cookie; the portal signs
	// in for them, as it does for any route
	if cookie, ok := f.consoleCookie(r); ok {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, consolePageMax))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("console %s: %d (Asked with %q)", p, resp.StatusCode, req.Header.Get("Cookie")[:min(len(req.Header.Get("Cookie")), 40)])
	}
	return b, nil
}

// versionedConsolePage is magpie's page with its own files named by their
// content's hash (magpie's versionedPage), and those files, which are what
// the console serves as its page.
func versionedConsolePage(raw []byte) ([]byte, map[string]bool) {
	files := map[string]bool{"index.html": true}
	at := time.Now().UTC()
	out := pageFile.ReplaceAllFunc(raw, func(m []byte) []byte {
		g := pageFile.FindSubmatch(m)
		if files[string(g[2])] {
			return m // asked for once
		}
		b, status := consoleFile(string(g[2]), at)
		if status != http.StatusOK {
			return m
		}
		files[string(g[2])] = true
		return []byte(fmt.Sprintf(`%s="%s?v=%s"`, g[1], g[2], contentHash(b)))
	})
	return out, files
}

// consoleFile is one of the page's files at a time, or a 404.
func consoleFile(name string, at time.Time) ([]byte, int) {
	if !pageFileAllowed(name) || !fsFile(name) {
		return nil, http.StatusNotFound
	}
	b, err := readPageFile(name)
	if err != nil {
		return nil, http.StatusNotFound
	}
	return b, http.StatusOK
}

// servePage is the console page to a signed-in person: magpie's page, its
// own, with the bootstrap this deployment writes before its scripts.
func (f *consoleFetch) servePage(w http.ResponseWriter, r *http.Request, id Identity) {
	page, _, err := f.loadPage(r)
	if err != nil {
		log.Printf("oidc portal: console page: %v", err)
		writeText(w, http.StatusBadGateway, "magpie's console is not reachable.\n")
		return
	}
	// whether it is an ordinary person's console (their own sidebar and
	// pages, their own data) or an admin's (magpie's own) is this person's,
	// not the portal's default (f.person): an admin's is magpie's whichever
	// the portal serves most.
	_, isPerson := f.personKey(id)
	if f.cfg.IsAdmin(id) {
		isPerson = false
	}
	pre := f.pre(id)
	// The page's own lines go just before its last script: start.js, whose
	// element stays in the page for the script after (boot.js is first).
	// An admin's console is magpie's, every view of it, and they add the
	// portals an admin opens to its sidebar. A person's go in one script
	// at the very end of the body, before </body> and inside it: a script
	// after </html> is never run.
	at := []byte(`<script src="start.js`)
	if isPerson {
		at = []byte("</body>")
	}
	i := len(page)
	if j := bytes.LastIndex(page, at); j >= 0 {
		i = j
	}
	whole := make([]byte, 0, len(page)+len(roleScript)+len(pre)+64)
	whole = append(whole, page[:i]...)
	if isPerson {
		// one element, run at the page's end: it uses nothing of the
		// page's but what its scripts left behind, as they did
		whole = append(whole, '<', 's', 'c', 'r', 'i', 'p', 't', ' ', 'i', 'd', '=', '"', 'o', 'i', 'd', 'c', '-', 'p', 'e', 'r', 's', 'o', 'n', '"', '>')
		whole = append(whole, pre...)
		whole = append(whole, '<', '/', 's', 'c', 'r', 'i', 'p', 't', '>')
	} else {
		// the role line runs from the page's first script (boot.js says it
		// too, before the page's own); here it is said inside the script
		// element adminPre brings, not as bare text of the page
		if j := bytes.Index(pre, []byte("(function(){")); j >= 0 {
			whole = append(whole, pre[:j]...)
			whole = append(whole, roleScript...)
			whole = append(whole, pre[j:]...)
		} else {
			whole = append(whole, roleScript...)
			whole = append(whole, pre...)
		}
	}
	whole = append(whole, page[i:]...)
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", strconv.Itoa(len(whole)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(whole)
}

// pre is the bootstrap after magpie's: whose console this is, and the lines
// this deployment adds. An admin's is magpie's console as it is, with the
// portal's pages in its sidebar; an ordinary person's is their own sidebar.
// An admin's is magpie's own, with the portal's pages in its sidebar; an
// ordinary person's is their own sidebar and their own data's pages (or,
// with no key yet, that sidebar alone).
func (f *consoleFetch) pre(id Identity) []byte {
	if f.cfg.IsAdmin(id) {
		return adminPre(id)
	}
	u, _ := f.personKey(id)
	return personScript(id, u)
}

// oidcPerson is the line both consoles start with: window.oidcPerson.
func oidcPerson(id Identity, u User, extra map[string]any) string {
	v := map[string]any{
		"email": id.Email, "name": id.Name, "sub": id.Subject,
		"keyId": u.KeyID,
	}
	for k, x := range extra {
		v[k] = x
	}
	return "window.oidcPerson=" + string(objJSON(v)) + ";"
}

// adminPre is magpie's console for an admin: magpie's own, every view of
// it, with the portal's pages (门户管理, 我的密钥, 退出登录) in its sidebar
// and the admin's address at its foot, put there as the sidebar is drawn.
func adminPre(id Identity) []byte {
	return []byte(`<script id="oidc-portal">(function(){
` + oidcPerson(id, User{}, map[string]any{"admin": true}) + `
var links=[["/admin","门户管理"],["/mine","我的密钥"],["/logout","退出登录"]];
// the Work pages are this deployment's machine's own: no role of the
// portal's reads them
function prune(){
 if(document.documentElement.classList.contains("oidc-pruned"))return;
 document.documentElement.classList.add("oidc-pruned");
 var nav=document.querySelector("#nav");if(!nav)return;
 ["agents","sessions","library"].forEach(function(v){var b=nav.querySelector('button[data-view="'+v+'"]');if(b)b.remove()});}
function add(){
 prune();var side=document.querySelector(".side-scroll");if(!side)return;
 if(!side.querySelector("#oidcPortalLinks")){var box=document.createElement("div");box.id="oidcPortalLinks";
  box.style.cssText="display:flex;flex-direction:column;gap:2px;padding:8px 6px;margin-bottom:6px;border-bottom:1px solid var(--line,rgba(0,0,0,.08))";
  links.forEach(function(l){var a=document.createElement("a");a.href=l[0];a.textContent=l[1];
   a.style.cssText="display:block;padding:6px 10px;border-radius:6px;color:inherit;text-decoration:none;font-size:13px";
   a.addEventListener("mouseenter",function(){a.style.background="var(--hover,rgba(0,0,0,.05))"});
   a.addEventListener("mouseleave",function(){a.style.background=""});
   box.appendChild(a);});
  var first=side.querySelector("#nav button[data-view]")||side.querySelector("#nav");
  // the page may list its views right after, which is then what is before
  if(first&&first.parentNode===side){side.insertBefore(box,first)}else{side.prepend(box)}}
 var foot=document.querySelector(".side-foot");
 if(foot&&!foot.querySelector("#oidcWho")){var d=document.createElement("div");d.id="oidcWho";
  d.style.cssText="padding:6px 10px;font-size:11px;color:var(--muted,#8a8a8e);overflow:hidden;text-overflow:ellipsis;white-space:nowrap";
  d.textContent=window.oidcPerson.email;foot.appendChild(d);}}
var n=0;function poll(){try{add()}catch(e){}if(n++<200)setTimeout(poll,50);}
if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",poll);else poll();})();</script>`)
}

// pageFileAllowed keeps a page's file name a plain path, not a way out.
func pageFileAllowed(name string) bool {
	return name == path.Clean(name) && !strings.HasPrefix(name, ".") && !strings.Contains(name, "..")
}

// personScript is an ordinary person's console: the page is magpie's, but
// it is built from every view of the whole deployment (供应商, 会话, 插件…),
// which this person is answered none of. Their sidebar is their own — magpie's
// own #nav, drawn by the page: the views left in it (我的密钥, 用量) are this
// deployment's, the rest of the page's hidden — and what it opens are pages
// registered as the page's own (kernel.js magpie.plugin), drawn in the
// page's own markup and colours. No return inside a function: a nested
// function whose line starts with a statement that ends in "}();" is not a
// function literal to the parser every script of a page goes through here
// (see inline_test.go).
//
// The person's pages draw from the portal's own answers (/portal/api/me,
// /portal/api/me/usage, /portal/api/my-key, /key/rotate), which say only the
// signed-in person's own key, limits and usage — never another key's, an
// account's or a provider's secret. The full key is the owner's alone: shown
// behind the page's own switch (the portal answers /portal/api/my-key to its
// own page, from this origin, never cross-site), and copied to the holder's
// clipboard only there.
func personScript(id Identity, u User) []byte {
	return []byte(`(function(){` + oidcPerson(id, u, nil) + `
// the page's own code looks into views a person is not given; its errors
// there are not this page's
window.addEventListener("error",function(e){var m=String(e&&e.message||"");if(/^Cannot (read|set) propert(ies|y) of null/.test(m)){e.preventDefault();e.stopImmediatePropagation();}},true);
// the page's words, in Chinese as every page of this deployment's is. Only
// the ones the page itself does not say: the rest are its own, already in
// its zh (i18n.js), and one said twice is a mistake the page reports
// oidcSay adds words of this deployment's as the page's, unless it already
// says them (a page of the portal's does; said twice is a mistake the page
// reports)
function oidcSay(d){var z={};for(var k in d){if(!(k in (typeof I18N!=="undefined"&&I18N.zh||{}))){z[k]=d[k]}}magpie.strings({zh:z})}
oidcSay({"Allowance":"额度","My key":"我的密钥","Tokens":"Tokens","No requests in this period yet.":"此时间段还没有请求。"});

// oidcText is a value escaped for the page, cut where it is long
function oidcText(s,n){s=String(s==null?"":s);if(n&&s.length>n)s=s.slice(0,n)+"…";return s}
// oidcAsk reads the portal's own answer for the person signed in
function oidcAsk(p){return fetch("/portal/api/"+p,{credentials:"same-origin",cache:"no-store"}).then(function(r){if(!r.ok)throw new Error(r.status);return r.json()})}
// oidcEl is the page's own way of making a row: a tag, its class, its text
function oidcEl(t,c,s){var e=document.createElement(t);if(c)e.className=c;if(s!==undefined)e.textContent=s;return e}
function oidcRow(name,sub){var r=oidcEl("div","row");var w=oidcEl("div","who");w.appendChild(oidcEl("div","name",name));if(sub)w.appendChild(oidcEl("div","sub",sub));r.appendChild(w);return r}
// oidcTime is a time in the page's own words
function oidcTime(t){try{var d=new Date(t);if(isNaN(d))return "—";return (d.getMonth()+1)+"月"+d.getDate()+"日 "+String(d.getHours()).padStart(2,"0")+":"+String(d.getMinutes()).padStart(2,"0")}catch(e){return "—"}}
// oidcNum is a token count as the page reads them
function oidcNum(n){n=+n||0;if(n>=1e9)return (n/1e9).toFixed(1)+"b";if(n>=1e6)return (n/1e6).toFixed(1)+"m";if(n>=1e4)return (n/1e3).toFixed(1)+"k";return String(n)}
// oidcMoney is a cost at list prices
function oidcMoney(v){v=+v||0;return v>=100?"$"+Math.round(v):"$"+v.toFixed(2)}

// the two pages the person opens, drawn by the page's own markup: a head
// of tabs (usage) and a .list of rows, as the page's own views are
function oidcMinePage(me){
var page=oidcEl("div");
var head=oidcEl("div","usage-head");
head.innerHTML='<div class="segs"><button class="opt on" type="button">概览</button></div>';
page.appendChild(head);
var list=oidcEl("div","list");page.appendChild(list);
// the key: masked as an address, full only behind the page's own switch
var keyRow=oidcRow(t("Key"),"");
var val=oidcEl("code","oidc-key oidc-hide");val.textContent=me.keyMasked||"—";val.title=t("Show key");
keyRow.appendChild(val);
list.appendChild(keyRow);
// the copy button: the owner's own, as the key page's is
var copy=oidcEl("button","text oidc-copy");copy.type="button";copy.textContent=t("Copy");
keyRow.appendChild(copy);
copy.onclick=function(){
 oidcAsk("my-key").then(function(d){
  var done=function(){copy.textContent=t("Copied");setTimeout(function(){copy.textContent=t("Copy")},1500)};
  if(navigator.clipboard&&navigator.clipboard.writeText){return navigator.clipboard.writeText(d.key).then(done)}
  var ta=document.createElement("textarea");ta.value=d.key;document.body.appendChild(ta);ta.select();document.execCommand("copy");ta.remove();done();
 }).catch(function(){copy.textContent=t("Copy failed");setTimeout(function(){copy.textContent=t("Copy")},1500)});
};
// the masked value opens the full key, its holder's alone; one click shows,
// another hides it again (the page's own switch on a .row)
val.onclick=function(){
 if(val.classList.contains("oidc-show")){val.classList.remove("oidc-show");val.textContent=me.keyMasked||"—";return}
 oidcAsk("my-key").then(function(d){val.textContent=d.key||"";val.classList.add("oidc-show")}).catch(function(){});
};
// the gateway address its clients are given
var urlRow=oidcRow("网关地址","");var uval=oidcEl("code","oidc-key");uval.textContent=me.url||location.origin;
uval.style.webkitUserSelect="text";uval.style.userSelect="text";urlRow.appendChild(uval);list.appendChild(urlRow);
// its budget
var budRow=oidcRow(t("Allowance"),me.budget||"");list.appendChild(budRow);
// its models, each a row of the list
if((me.models||[]).length){
 var mh=oidcEl("div","row-head");mh.appendChild(oidcEl("span","label",t("Models this key may use")));page.appendChild(mh);
 var ml=oidcEl("div","list");
 for(var i=0;i<me.models.length;i++){var mr=oidcRow(me.models[i],"");mr.querySelector(".name").className="name mono";ml.appendChild(mr)}
 page.appendChild(ml);
}
// the rotate button, the page's own: confirmation, then the portal's own
// call, which never shows the new value (only its holder's click copies it)
var rh=oidcEl("div","row-head");page.appendChild(rh);
var rl=oidcEl("div","list");var rr=oidcRow("","");
var bt=oidcEl("button","text danger");bt.type="button";bt.textContent=t("Rotate key");
rr.appendChild(bt);rl.appendChild(rr);page.appendChild(rl);
bt.onclick=function(){
 if(bt.dataset.armed){delete bt.dataset.armed;bt.classList.remove("busy");
  fetch("/key/rotate",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:"{}"})
   .then(function(r){if(!r.ok)throw new Error(r.status);return r.json()})
   .then(function(d){bt.textContent=t("Rotated");oidcAsk("my-key").then(function(){});
    me.keyMasked="…"+String(d.key||"").slice(-4);
    val.classList.remove("oidc-show");val.textContent=me.keyMasked;
    setTimeout(function(){bt.textContent=t("Rotate key")},2000)})
   .catch(function(){bt.textContent=t("Rotation failed");setTimeout(function(){bt.textContent=t("Rotate key")},2000)});
  return}
 bt.dataset.armed="1";bt.classList.add("busy");bt.textContent=t("Rotate? The old key stops working at once; every client needs the new one.");
 setTimeout(function(){if(bt.dataset.armed){delete bt.dataset.armed;bt.classList.remove("busy");bt.textContent=t("Rotate key")}},6000);
};
return page;
}

function oidcUsagePage(u){
var page=oidcEl("div");
var head=oidcEl("div","usage-head");
var segs=oidcEl("div","segs");
var PS=[["today","今天"],["week","最近 7 天"],["month","最近 30 天"],["all","全部"]];
var cur=location.search.indexOf("period=")>-1?(location.search.match(/period=(\w+)/)||[])[1]:"month";
for(var i=0;i<PS.length;i++){(function(p,label){
 var b=oidcEl("button","opt"+(p===cur?" on":""));b.type="button";b.textContent=label;
 b.onclick=function(){
  // the period is in the address, the page open's after it (?view=oidc-usage):
  // the page's own show runs open again, which draws the period's figures
  var q=new URLSearchParams(location.search);q.set("period",p);
  history.replaceState(null,"","?"+q);
  var r=typeof show==="function"?show("oidc-usage"):null;if(r&&r.catch){r.catch(function(e){})}
 };
 segs.appendChild(b);
})(PS[i][0],PS[i][1])}
head.appendChild(segs);
var tot=u.totals||{};
var cost=oidcEl("span","usage-cost");cost.innerHTML="<b>"+oidcMoney(tot.cost)+"</b>";head.appendChild(cost);
page.appendChild(head);
// the period's figures, the page's own tiles
var stats=oidcEl("section","stats");
var tile=function(n,label,sub){var k=oidcEl("div","kpi");var b=oidcEl("b","",n);k.appendChild(b);k.appendChild(oidcEl("span","",label));if(sub)k.appendChild(oidcEl("small","",sub));return k};
stats.appendChild(tile(oidcNum(tot.tokens),t("Tokens"),""));
stats.appendChild(tile(String(tot.calls||0),t("Requests"),""));
stats.appendChild(tile(oidcMoney(tot.cost),t("Cost"),""));
stats.appendChild(tile(oidcNum(tot.input),"输入",""));
page.appendChild(stats);
// each model's calls, a row of a list
if((u.models||[]).length){
 var mh=oidcEl("div","row-head");mh.appendChild(oidcEl("span","label",t("Model")));page.appendChild(mh);
 var ml=oidcEl("div","list");
 for(var i=0;i<u.models.length;i++){(function(m){
  var r=oidcRow(m.model||"—",m.calls+" 次 · "+oidcNum(m.tokens)+" tokens"+(m.cost?" · "+oidcMoney(m.cost):""));
  r.appendChild(oidcEl("div","oidc-num",oidcNum(m.input)+" → "+oidcNum(m.output)));
  ml.appendChild(r);
 })(u.models[i])}
 page.appendChild(ml);
}
// the recent requests: metadata only, their bodies in Langfuse
if((u.recent||[]).length){
 var rh=oidcEl("div","row-head");rh.appendChild(oidcEl("span","label",t("Requests")));page.appendChild(rh);
 var wrap=oidcEl("div","oidc-led");
 var table=oidcEl("table","led");
 var thead=oidcEl("thead");var hr=oidcEl("tr");
 [t("Time"),t("Model"),t("Status"),t("Tokens")].forEach(function(h){hr.appendChild(oidcEl("th","",h))});
 thead.appendChild(hr);table.appendChild(thead);
 var tbody=oidcEl("tbody");
 for(var i=0;i<u.recent.length;i++){(function(q){
  var tr=oidcEl("tr");if(String(q.status).charAt(0)!=="2"&&String(q.status)!=="")tr.className="bad";
  tr.appendChild(oidcEl("td","when",oidcTime(q.time)));
  tr.appendChild(oidcEl("td","model",oidcText(q.model,40)));
  tr.appendChild(oidcEl("td","st",q.status===""?"—":String(q.status)));
  tr.appendChild(oidcEl("td","n",oidcNum(q.tokens)));
  tbody.appendChild(tr);
 })(u.recent[i])}
 table.appendChild(tbody);wrap.appendChild(table);
 var note=oidcEl("p","oidc-note2",t("Only the request metadata is shown; the request and response bodies are in Langfuse."));
 wrap.appendChild(note);page.appendChild(wrap);
}else{page.appendChild(oidcEl("p","led-none",t("No requests in this period yet.")))}
return page;
}

// the person's pages, registered as the page's own (kernel.js): they are
// shown by its own show(), in its own sidebar, with its own styling — no
// page of this deployment's is theirs
magpie.plugin("oidc-person",function(ctx){
// the view's own column of rows (console.css: .oidc-page), mounted into
// the page's own main: the page's kernel mounts part.html and runs open
// for its loading — the element open draws is the caller's, not the
// kernel's, so the drawing goes into #view-<key> itself
ctx.slots.add("page",{key:"mine",html:"",open:function(){
 var main=document.getElementById("view-mine");if(!main)return;
 var p=document.createElement("div");p.className="oidc-page";
 main.replaceChildren(p);
 p.appendChild(oidcEl("div","oidc-loading",t("Loading…")));
 var out=oidcAsk("me").then(function(me){
  p.replaceChildren(oidcMinePage(me));
 }).catch(function(){p.replaceChildren(oidcEl("p","led-none","—"))});
 return out;
}});
ctx.slots.add("page",{key:"oidc-usage",html:"",open:function(){
 var main=document.getElementById("view-oidc-usage");if(!main)return;
 var p=document.createElement("div");p.className="oidc-page";
 main.replaceChildren(p);
 p.appendChild(oidcEl("div","oidc-loading",t("Loading…")));
 var cur=location.search.indexOf("period=")>-1?"?"+location.search.match(/period=(\w+)/)[0]:"";
 var out=oidcAsk("me/usage"+cur).then(function(u){
  p.replaceChildren(oidcUsagePage(u));
 }).catch(function(){p.replaceChildren(oidcEl("p","led-none","—"))});
 return out;
 }});
});

// navItem is a button of the page's sidebar, as the page draws its own: the
// sidebar's button out of the header's #nav (the page moves it there by the
// class it gives it), an icon and its name. Its click does what the page's
// own does (app.js show), whichever element it now lives in.
function navItem(key,en,icon,on){
var b=document.createElement("button");
b.type="button";b.dataset.view=key;b.className="side-btn oidc-keep";
b.innerHTML='<svg class="nav-ic" viewBox="0 0 20 20" width="16" height="16" aria-hidden="true"><g fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">'+icon+'</g></svg><span data-t data-en="'+en+'">'+oidcText(t(en),20)+'</span>';
b.onclick=function(){var r=typeof show==="function"?show(key):null;if(r&&r.catch){r.catch(function(e){})}};
if(on){b.classList.add("on");b.setAttribute("aria-current","page")}
return b;
}
var MINE_ICON='<rect x="3.5" y="4.5" width="13" height="11" rx="2"/><path d="M7 4.5V3a1.5 1.5 0 0 1 1.5-1.5h3A1.5 1.5 0 0 1 13 3v1.5"/>';

// mark is the person's sidebar and title line: the page's own #nav is
// which view is open; what the sidebar shows is these two pages alone.
// the page moves its own buttons into the sidebar, so it is that which is
// rebuilt, not the #nav it moved them out of
function mark(){
var nav=document.querySelector("#nav");if(!nav){return}
var title=document.querySelector("#pageTitle"),tt=title?title.textContent:"";
if(!tt){tt=t(wantedView()==="oidc-usage"?"Usage":"My key")}
// The sidebar is where the page put its #nav (layoutNav moves it, and finds
// its buttons in it): what is in it is the nav, 我的密钥 and 用量, and
// nothing of the page's — its own buttons, its groups' lines, the line drawn
// to the button open. The page moves its buttons about as it likes: what it
// moved in goes back where it was, one that is right already is left alone.
var side=nav.parentNode&&nav.parentNode.nodeType===1?nav.parentNode:nav;
// done is the nav holding these two pages alone: a button of the page's
// (供应商, 会话, …) is still in it until mark has had its way once
var mineBtn=side.querySelector('button[data-view="mine"]');
var usageBtn=side.querySelector('button[data-view="oidc-usage"],button[data-view="usage"]');
var found=!!(mineBtn&&usageBtn);
if(!found){
 var usage=usageBtn||navItem("usage","Usage","",false);
 var mine=mineBtn||navItem("mine","My key",MINE_ICON,tt===t("My key")||tt==="我的密钥");
 if(usage.parentNode!==nav){nav.appendChild(usage)}
 if(mine.parentNode!==nav){nav.appendChild(mine)};
 // the page's own nav as the page drew it; the button open, where it is
 // not one of the two, is 我的密钥's (the first one's)
 var first=this&&this.dataset&&this.dataset.view?this:null;
 var all=shown(nav);
 for(var i=0;i<all.length;i++){var b=all[i];
  if(b===usage||b===mine){continue}
  if(first&&b.contains(first)){
   var ns=b.querySelector("span");if(ns){ns.textContent=t("My key");ns.dataset.en="My key"}
   b.dataset.view="mine";mine=b;continue}
  b.remove()}
 var rest=nav.querySelectorAll(".nav-gl,.nav-top-hl");
 for(var i=0;i<rest.length;i++){rest[i].remove()}
 if(usage&&!usage.dataset.oidc){
  usage.dataset.oidc="1";
  var sp=usage.querySelector("span");
  if(sp){sp.textContent=t("Usage");sp.dataset.en="Usage"}
  usage.onclick=function(){var r=typeof show==="function"?show("usage"):null;if(r&&r.catch){r.catch(function(e){})}};
 }
 var kids=Array.prototype.slice.call(side.childNodes);
 for(var i=0;i<kids.length;i++){var c=kids[i];
  if(c===nav){continue}
  if(c.nodeType===3&&!c.textContent.trim()){continue}
  c.parentNode&&c.parentNode.removeChild(c)}
}else{
 // the page moved one of them where it lists a view (hidden there): back
 var moved=side.querySelectorAll("button[data-view]");
 for(var i=0;i<moved.length;i++){var b=moved[i];if(b.parentNode!==nav){nav.appendChild(b)}}
}
var bs=side.querySelectorAll("button[data-view]");
for(var i=0;i<bs.length;i++){
 var on=bs[i].querySelector("span")?bs[i].querySelector("span").textContent===tt:false;
 bs[i].classList.toggle("on",on);bs[i].hidden=false;
 if(on){bs[i].setAttribute("aria-current","page")}else{bs[i].removeAttribute("aria-current")}}
var foot=document.querySelector(".side-foot");
if(foot&&!foot.querySelector("#oidcSideWho")){var d=document.createElement("div");d.id="oidcSideWho";d.textContent=window.oidcPerson.email;foot.appendChild(d)}
var crumb=document.querySelector("#crumb");if(crumb){crumb.hidden=true}
var ids=["#sync","#open","#winclose","#prefs","#updateHide"];
for(var i=0;i<ids.length;i++){var b=document.querySelector(ids[i]);if(b&&b.tagName==="BUTTON"){b.hidden=true}}
var up=document.querySelector("#update");if(up){up.hidden=true}
if(typeof magpie!=="undefined"&&magpie.page&&magpie.page("mine")){magpie.page("mine").title=t("My key")}
var v=null;for(var i=0;i<bs.length;i++){if(bs[i].classList.contains("on")){v=bs[i].dataset.view}}
if(v){var href="/?view="+(v==="usage"?"oidc-usage":v);if(location.pathname!=="/"||location.search!==href.slice(1)){history.replaceState(null,"",href)}}
}
// shown is the buttons of a nav a reader sees: the page leaves out the
// pages it has switched off (navHides), and those of the whole deployment's
// are no one's to count on
function shown(n){var out=[],all=n.querySelectorAll("button[data-view]");for(var i=0;i<all.length;i++){if(!all[i].hidden){out.push(all[i])}}return out}
// text is what an element says, however it says it
function text(n){return n.innerText!==undefined?(n.innerText||""):(n.textContent||"")}
// wantedView is the page the address asks for, 我的密钥 unless 用量's
function wantedView(){var w=new URLSearchParams(location.search).get("view");return w==="oidc-usage"?"oidc-usage":"mine"}

// the person's pages are in the page's sidebar once its own are drawn
var tries=0;
function build(){
if(document.querySelector("#oidc-built")){return}
var nav=document.querySelector("#nav");
if(!nav||!text(document.querySelector("#view-usage")||{})||shown(nav).length<1){tries++;if(tries<400){setTimeout(build,50)}else{done()}return}
done();
}
function done(){
if(document.querySelector("#oidc-built")){return}
var s=document.createElement("div");s.id="oidc-built";s.hidden=true;document.body.appendChild(s);
mark();
// the page opens on the person's page (我的密钥), whatever it kept
var want=wantedView();
var r=typeof show==="function"?show(want):null;if(r&&r.catch){r.catch(function(e){})}
if(typeof setGatewayMode==="function"){setGatewayMode(false)}
// the page's own title line is watched: the view open is read from it, and
// the sidebar redrawn to match (a person's pages only)
var title=document.querySelector("#pageTitle");
if(title){new MutationObserver(function(){mark()}).observe(title,{childList:true,subtree:true,characterData:true})}
setInterval(mark,1000);
}
if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",build)}else{build()}
})();`)
}

// personCSS is what a person's console adds to magpie's page: very little,
// for their pages are drawn in the page's own markup and classes already —
// only the key's full value as a select-free line, a request table's wrap,
// and the person's address at the sidebar's foot.
const personCSS = `.oidc-person .oidc-key { font: 500 12px/1.4 var(--code); padding: 2px 7px; border-radius: 6px; background: var(--pill); overflow-wrap: anywhere; user-select: text; -webkit-user-select: text; cursor: default; flex: none; max-width: 60%; }
.oidc-person .oidc-key.oidc-show { background: var(--accent-soft); color: var(--accent); }
.oidc-person .oidc-num { color: var(--muted); font-variant-numeric: tabular-nums; font-size: 11.5px; white-space: nowrap; }
.oidc-person .oidc-page { display: flex; flex-direction: column; min-height: 0; }
.oidc-person .oidc-loading { padding: 36px 20px; text-align: center; color: var(--muted); }
.oidc-person .oidc-led { background: var(--card); border: 1px solid var(--line); border-radius: 12px; overflow: hidden; flex: none; }
.oidc-person .oidc-led .oidc-note2 { padding: 8px 12px; margin: 0; border-top: 1px solid var(--line-2); color: var(--muted); font-size: 11px; }
.oidc-person .oidc-key { white-space: nowrap; word-break: normal; }
.oidc-person .oidc-right { display: flex; align-items: center; gap: 8px; margin-left: auto; min-width: 0; flex-wrap: wrap; justify-content: flex-end; }
.oidc-person .oidc-val { color: var(--muted); font-size: 12px; font-variant-numeric: tabular-nums; white-space: nowrap; }
.oidc-person .row.link { cursor: pointer; }
.oidc-person .row.link:hover { background: var(--pill); }
.oidc-person p.oidc-notice, .oidc-person p.oidc-error { margin: 4px 0 6px; padding: 8px 12px; border-radius: 9px; font-size: 12.5px; }
.oidc-person p.oidc-notice { background: var(--accent-soft, var(--pill)); color: var(--fg); }
.oidc-person p.oidc-error { background: var(--red-soft, var(--pill)); color: var(--red); }
.oidc-person .oidc-head { padding-left: 2px; }
.oidc-person .oidc-text { margin: 2px 0 6px; color: var(--fg-2, inherit); }
.oidc-person .oidc-field input, .oidc-person .oidc-field textarea, .oidc-person .oidc-field select { font: inherit; font-size: 12.5px; color: var(--fg); background: var(--card); border: 1px solid var(--line); border-radius: 7px; padding: 4px 8px; max-width: 260px; min-width: 0; }
.oidc-person .oidc-field textarea { width: 260px; resize: vertical; }
.oidc-person .oidc-field.wide input, .oidc-person .oidc-field.wide textarea { width: 100%; max-width: 100%; }
.oidc-person .oidc-field.wide .who { flex: 1 1 100%; }
.oidc-person .oidc-form .oidc-fields { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 0 14px; padding: 0 6px; }
.oidc-person .oidc-form .oidc-fields > .row { border-bottom: 1px solid var(--line-2); flex-wrap: wrap; }
.oidc-person .oidc-form .oidc-fields > .row.wide { grid-column: 1 / -1; }
.oidc-page .oidc-block { display: flex; flex-direction: column; gap: 6px; margin-bottom: 16px; }
.oidc-page .oidc-block > .row-head { margin-top: 2px; }
.oidc-person .oidc-acts { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; padding: 8px 9px 8px 11px; }
.oidc-person .oidc-acts:empty { display: none; }
.oidc-person .oidc-form .oidc-acts { padding-left: 11px; }
.oidc-person .oidc-row > .oidc-acts { padding: 0; }
.oidc-person .oidc-key { cursor: pointer; }
.oidc-person #oidcSideWho { padding: 8px 10px 2px; font-size: 11px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
`
