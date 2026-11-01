package oidcportal

import (
	"io"
	"net/http"
)

// pageJS is /portal/page.js, the script a page of the portal's in magpie's
// frame runs (magpiepage.go): it draws what the page says it draws
// (#oidc-page) in magpie's own elements and classes, and puts the page's
// pages in its sidebar. What it draws is the portal's own; magpie's page of
// the whole deployment is not one of them, so nothing of this page is a
// view of it.
//
// The element is read at the page's end, after kernel.js, and the frame is
// magpie's (index.html): the sidebar's #nav, the header's #pageTitle and
// #crumb, and the view. No return inside a function: a nested function
// whose line starts with a statement that ends in "}();" is not a function
// literal to the parser every script of a page goes through here (see
// inline_test.go).
func (s *Server) pageJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.WriteString(w, pageScript)
}

const pageScript = `(function(){
// its lines go after magpie's kernel.js, so they may say what it does (a
// frame without it still draws, in its page's own words)
var hasMagpie=typeof magpie!=="undefined"&&magpie&&typeof magpie.strings==="function";
var box=document.getElementById("oidc-page");
var D={};try{D=JSON.parse(box?box.textContent:"{}")||{}}catch(e){D={}}
if(document.documentElement){document.documentElement.className+=" oidc-person"}
// the page's words, in Chinese: only the ones this script says itself
if(hasMagpie){var words={zh:{
"Copied":"已复制","Copy failed":"复制失败","Gateway address":"网关地址","Allowance":"额度",
"Only the request metadata is shown; the request and response bodies are in Langfuse.":"这里只显示请求的元数据；请求和响应正文请在 Langfuse 查看。",
"Rotate? The old key stops working at once; every client needs the new one.":"轮换后旧密钥立即失效，需要把新密钥换到每个客户端。",
"Saved":"已保存","This time frame":"这个时间段"}};
// unless the page already says them: one said twice is a mistake it reports
var z={};for(var k in words.zh){if(!(k in (typeof I18N!=="undefined"&&I18N.zh||{}))){z[k]=words.zh[k]}}
magpie.strings({zh:z});}

// el is the page's way of making an element: a tag, its parts
function el(t,c,text){var e=document.createElement(t);if(c)e.className=c;if(text!=null&&text!=="")e.textContent=text;return e}
var $=function(s){return document.querySelector(s)};

// each of the sidebar's pages, as the page's own buttons are: an icon, then
// its name; the page open is on
var NAVIC={
 mine:'<rect x="3.5" y="4.5" width="13" height="11" rx="2"/><path d="M7 4.5V3a1.5 1.5 0 0 1 1.5-1.5h3A1.5 1.5 0 0 1 13 3v1.5"/>',
 "oidc-usage":'<path d="M3 16V9M8 16V4M13 16v-5M18 16v-9"/>',
 admin:'<path d="M3.5 5h13M3.5 10h13M3.5 15h9"/>',
 console:'<rect x="3" y="4" width="14" height="12" rx="2"/><path d="M6.5 8.5l2.5 2-2.5 2M10.5 12.5h3"/>',
 logout:'<path d="M11.5 3.5h3A1.5 1.5 0 0 1 16 5v10a1.5 1.5 0 0 1-1.5 1.5h-3M8 12.5L11 10 8 7.5M11 10H3.5"/>'
};
function navIcon(key){
 var s=document.createElementNS("http://www.w3.org/2000/svg","svg");
 s.setAttribute("viewBox","0 0 20 20");s.setAttribute("width","16");s.setAttribute("height","16");s.setAttribute("class","nav-ic");s.setAttribute("aria-hidden","true");
 s.innerHTML='<g fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">'+(NAVIC[key]||NAVIC.mine)+"</g>";
 return s;
}
function drawNav(){
 var nav=$("#nav");if(!nav){return}
 nav.replaceChildren();
 nav.removeAttribute("class");nav.setAttribute("role","navigation");
 (D.pages||[]).forEach(function(p){
  var b=el("a",(p.view?"view-btn":"")+(p.key===D.open?" on":""));
  b.setAttribute("href",p.href||"#");
  if(p.key===D.open)b.setAttribute("aria-current","page");
  b.appendChild(navIcon(p.key));
  b.appendChild(el("span","",""+t(p.label)));
  nav.appendChild(b);
 });
 var title=$("#pageTitle");if(title)title.textContent=D.title||"";
 var foot=document.querySelector(".side-foot");
 if(foot){var old=foot.querySelector(".oidc-who");if(D.person&&!old){foot.appendChild(el("div","oidc-who",D.person))}else if(D.person&&old){old.textContent=D.person}}
 var crumb=$("#crumb");
 if(crumb&&D.crumb){
  crumb.hidden=false;
  crumb.replaceChildren.apply(crumb,D.crumb.split(" / ").flatMap(function(c,i){var parts=[];if(i)parts.push(el("i","","/"));parts.push(el("span","",c));return parts}));
 }
 document.title=(D.title?D.title+" · ":"")+"magpie";
}

// a button of an action: the form's own (submit), or the page's — a link
// away, a route posted as a form of the portal's, the one here on (on)
function actButton(a){
 var btn;
 if(a.kind==="on"||a.kind==="seg-on"){
  btn=el("button","opt on",t(a.label));btn.type="button";btn.disabled=true;return btn;
 }
 var acts=a.submit||a.post||a.href;
 if(a.submit){btn=el("button","text"+(a.kind==="primary"?" primary":"")+(a.kind==="danger"?" danger":""),t(a.label));btn.type="submit"}
 else{
  btn=el(acts?"button":"span","text"+(a.kind==="primary"?" primary":"")+(a.kind==="danger"?" danger":""),t(a.label));
  if(!acts){return btn}
  btn.type="button";
  btn.onclick=function(){
   if(a.confirm&&!window.confirm(t(a.confirm))){return}
   if(a.post){submitTo(a.post,a.sub)}
   else if(a.href){go(a.href)}
  };
 }
 return btn;
}
// go is the page's own links: inside the frame, never a new tab
function go(href){window.location.assign(href)}
// submitTo is a form of the page: its fields and the action's own, posted
// as a form of the portal's (the same route, the same checks)
function submitTo(post,sub,fields){
 var f=el("form");f.method="post";f.action=post;
 if(sub){var s=el("input");s.type="hidden";s.name="sub";s.value=sub;f.appendChild(s)}
 Object.keys(fields||{}).forEach(function(k){var i=el("input");i.type="hidden";i.name=k;i.value=fields[k];f.appendChild(i)});
 document.body.appendChild(f);f.submit();
}

function tag(text,on){
 var e=el("span","badge "+(on==="good"?"free":on==="bad"?"off":on==="warn"?"warn":"mute"),text);
 e.style.height="16px";e.style.lineHeight="16px";e.style.padding="0 6px";
 if(on==="good"){e.style.background="var(--green-soft)";e.style.color="var(--green)"}
 else if(on==="bad"){e.style.background="var(--red-soft)";e.style.color="var(--red)"}
 else if(on==="warn"){e.style.background="var(--amber-soft)";e.style.color="var(--amber)"}
 else{e.style.background="var(--pill)";e.style.color="var(--muted)";e.style.boxShadow="inset 0 0 0 1px var(--line)"}
 return e;
}
function buttonBox(acts){
 var b=el("div","oidc-acts");
 (acts||[]).forEach(function(a){b.appendChild(actButton(a))});
 return b;
}
function row(r){
 var e=el("div","row oidc-row"+(r.href?" link":""));
 var who=el("div","who");
 who.appendChild(el("div","name"+(r.mono?" mono":""),r.name));
 if(r.sub)who.appendChild(el("div","sub",""+r.sub));
 if(r.note)who.appendChild(el("div","sub oidc-note",r.note));
 e.appendChild(who);
 var right=el("div","oidc-right");
 if(r.text)right.appendChild(el("span","oidc-val",""+r.text));
 if(r.code)right.appendChild(el("code","oidc-key",""+r.code));
 if(r.tag)right.appendChild(tag(t(r.tag),r.tagOn));
 if(r.acts&&r.acts.length)right.appendChild(buttonBox(r.acts));
 if(r.href)e.classList.add("link");
 e.appendChild(right);
 return e;
}
// linkRow is a row that opens something: its own address, and keys work
function linkRow(r){
 var e=row(r);
 if(r.href){e.tabIndex=0;e.setAttribute("role","link");e.onclick=function(){go(r.href)};e.onkeydown=function(ev){if(ev.key==="Enter"){go(r.href)}}}
 return e;
}
function statsOf(stats,head){
 var s=el("section","stats");
 var tile=function(v,label,sub){var k=el("div","kpi");k.appendChild(el("b","",""+v));k.appendChild(el("span","",""+label));if(sub)k.appendChild(el("small","",""+sub));return k};
 (stats||[]).forEach(function(x){s.appendChild(tile(x.value,x.label,x.sub))});
 return s;
}
function tableOf(tb){
 var wrap=el("div","oidc-led");
 var table=el("table","led");
 var thead=el("thead");var hr=el("tr");
 (tb.head||[]).forEach(function(h){hr.appendChild(el("th","",h))});thead.appendChild(hr);table.appendChild(thead);
 var body=el("tbody");
 (tb.rows||[]).forEach(function(cells,i){
  var tr=el("tr");if(tb.bad&&tb.bad[i])tr.className="bad";
  cells.forEach(function(c,j){
   var td=el("td",j===0?"when":j===cells.length-1?"n":"",""+c);
   if(j===cells.length-1&&/^\d+ (ms|s)$/.test(c))td.className="n";
   // the last cell that is an address here is the line's own link
   if(j===cells.length-1&&/^\/(admin|\?)/.test(c)){td.replaceChildren();var a=el("a","text action","打开");a.href=c;a.style.textDecoration="none";td.appendChild(a);td.className="n"}
   tr.appendChild(td);
  });
  body.appendChild(tr);
 });
 table.appendChild(body);
 if(!(tb.rows||[]).length){return el("p","led-none",t("No requests in this period yet."))}
 wrap.appendChild(table);
 if(tb.note)wrap.appendChild(el("p","oidc-note2",t(tb.note)));
 return wrap;
}
// the words of a form's values (the standing, the limit's period)
var WORDS={"":t("All"),requested:t("Requested"),active:t("Active"),pending:t("Pending"),disabled:t("Disabled"),rejected:t("Rejected"),
 day:t("every day"),week:t("every week"),month:t("every month"),days:t("every N days"),hours:t("every N hours")};
function word(v){return WORDS[v]||v}
// tabsOf is a form's line of tabs: the one open on, and the links to the
// others (the page again, the period asked for)
function tabsOf(acts){
 var segs=el("div","segs");
 (acts||[]).forEach(function(a){segs.appendChild(actButton(a))});
 return segs;
}
// formOf is a form of the page: its fields as rows of a list, its buttons
// under them; a form without fields is its tabs, or its buttons
function formOf(f){
 if(!f.post){return null}
 var box=el("form","oidc-form");box.method=f.get?"get":"post";box.action=f.post;
 if(f.sub){var h=el("input");h.type="hidden";h.name="sub";h.value=f.sub;box.appendChild(h)}
 if(f.tabs&&f.tabs.length)box.appendChild(tabsOf(f.tabs));
 var list=el("div","list oidc-fields");
 (f.fields||[]).forEach(function(x){
  if(x.kind==="hidden"){var hi=el("input");hi.type="hidden";hi.name=x.name;hi.value=x.value||"";box.appendChild(hi);return}
  var r=el("div","row oidc-field"+(x.wide?" wide":""));
  var who=el("div","who");who.appendChild(el("label","name",x.label));
  if(x.note)who.appendChild(el("div","sub",x.note));
  r.appendChild(who);
  var v;
  if(x.kind==="textarea"){v=el("textarea");v.rows=3;v.value=x.value||""}
  else if(x.kind==="select"){
   v=el("select");
   (x.options||[]).forEach(function(o){var op=el("option");op.value=o;op.textContent=word(o);v.appendChild(op)});
   v.value=x.value||"";
  }else{v=el("input");v.type=x.kind==="number"?"text":"text";v.inputMode=x.kind==="number"?"decimal":"text";v.value=x.value||""}
  v.name=x.name;r.appendChild(v);list.appendChild(r);
 });
 box.appendChild(list);
 var bar=el("div","oidc-acts");
 (f.acts||[]).forEach(function(a){bar.appendChild(actButton(a))});
 box.appendChild(bar);
 return box;
}
function tabsSegs(tabs){
 var segs=el("div","segs");
 (tabs||[]).forEach(function(x){var b=el("button","opt"+(x.on?" on":""),x.label);b.type="button";if(!x.on)b.disabled=true;segs.appendChild(b)});
 return segs;
}
function blockOf(b){
 var out=el("div","oidc-block");
 if(b.head)out.appendChild(el("div","row-head oidc-head",b.head));
 if(b.note)out.appendChild(el("p","oidc-note",t(b.note)));
 if(b.text)out.appendChild(el("p","oidc-text",t(b.text)));
 var tabs=b.tabs||[];
 if(tabs.length){
  out.appendChild(tabsSegs(tabs));
  tabs.forEach(function(x){
   if(x.stats&&x.stats.length)out.appendChild(statsOf(x.stats));
   var list=el("div","list");(x.rows||[]).forEach(function(r){list.appendChild(row(r))});out.appendChild(list);
  });
 }else if(b.rows&&b.rows.length){
  var list=el("div","list");b.rows.forEach(function(r){list.appendChild(linkRow(r))});out.appendChild(list);
 }
 if(b.items&&b.items.length){
  var il=el("div","list");b.items.forEach(function(i){il.appendChild(row({name:i.name,sub:i.sub,mono:true}))});out.appendChild(il);
 }else if(b.items&&!b.items.length&&b.head){
  out.appendChild(el("p","led-none","—"));
 }
 if(b.stats&&b.stats.length)out.appendChild(statsOf(b.stats));
 var f=b.form?formOf(b.form):null;
 if(f)out.appendChild(f);
 else if(b.form&&b.form.tabs)out.appendChild(tabsOf(b.form.tabs));
 else if(b.form&&b.form.acts&&b.form.acts.length)out.appendChild(buttonBox(b.form.acts));
 if(b.table)out.appendChild(tableOf(b.table));
 if(b.acts&&b.acts.length)out.appendChild(buttonBox(b.acts));
 return out;
}
function drawBody(){
 var main=$("#view-oidc");if(!main){return}
 main.replaceChildren();
 if(D.notice)main.appendChild(el("p","oidc-notice",t(D.notice)));
 if(D.error)main.appendChild(el("p","oidc-error",t(D.error)));
 (D.blocks||[]).forEach(function(b){main.appendChild(blockOf(b))});
}
function build(){
 drawNav();drawBody();
}
if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",build)}else{build()}
})();`
