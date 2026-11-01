package oidcportal

import (
	"encoding/json"
	"net/url"
	"strings"
)

// magpiePage is a page of the portal's drawn in magpie's own frame: the
// same scripts magpie's page runs (consolepage.go serves them), its own
// kernel.js drawing the page from what this file says before them. The
// portal's management pages (门户管理, a person), the pages a person
// without a key is shown, and its errors are all this page: a sidebar of
// the portal's pages, magpie's markup and styling (app.css), Chinese.
//
// The page says what it draws as data (magpiePageData), and magpiePageScript
// (console.go, served at /portal/page.js) turns it into the page's own
// elements: a head of tabs (.segs) and rows of a .list, tables of .led,
// forms of inputs and the page's buttons (.text). What is drawn is this
// deployment's; magpie's page of the whole deployment is not one of them.

// magpiePageData is what a magpie-framed page draws: its title line, the
// sidebar's pages (this one marked on), a notice or an error, and what
// falls under it.
type magpiePageData struct {
	// Title is the line above the content (#pageTitle's).
	Title string `json:"title"`
	// Crumb is the small line above the title.
	Crumb string `json:"crumb,omitempty"`
	// Person is whose console it is: the address at the sidebar's foot.
	Person string `json:"person,omitempty"`
	// Pages is the sidebar: a page of the portal's, or a link away.
	Pages []magpiePageRef `json:"pages,omitempty"`
	// Open is the key of Pages open.
	Open string `json:"open,omitempty"`
	// Assets is the page's own stylesheet's address, with its version.
	Assets string `json:"assets,omitempty"`
	// Notice is a line of good news (saved, rotated); Error one of bad.
	Notice string `json:"notice,omitempty"`
	Error  string `json:"error,omitempty"`
	// Blocks are what the page draws, in order.
	Blocks []pageBlock `json:"blocks,omitempty"`
}

// magpiePageRef is one of the sidebar's pages: a page in this frame (View),
// or a link away (Href).
type magpiePageRef struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Href  string `json:"href,omitempty"`
	View  bool   `json:"view,omitempty"`
}

// pageBlock is one of a page's sections: its heading, what it says above
// its rows, and its rows, table or form. A block with Rows and Acts draws
// its buttons under its rows.
type pageBlock struct {
	Head  string     `json:"head,omitempty"`
	Note  string     `json:"note,omitempty"`
	Rows  []pageRow  `json:"rows,omitempty"`
	Table *pageTable `json:"table,omitempty"`
	Form  *pageForm  `json:"form,omitempty"`
	// Stats are a block's figures (.stats); Tabs a head of tabs, the period
	// open on, each with its own figures and rows.
	Stats []pageStat `json:"stats,omitempty"`
	Tabs  []pageTab  `json:"tabs,omitempty"`
	// Text is what it says above its rows; Acts are the buttons under them.
	Text  string     `json:"text,omitempty"`
	Acts  []pageAct  `json:"acts,omitempty"`
	Items []pageItem `json:"items,omitempty"`
}

// pageTab is one of a block's tabs: its label, and the figures and rows it
// draws.
type pageTab struct {
	Label string     `json:"label"`
	On    bool       `json:"on,omitempty"`
	Stats []pageStat `json:"stats,omitempty"`
	Rows  []pageRow  `json:"rows,omitempty"`
}

// pageStat is one figure of a .stats grid: its number, its label, a note.
type pageStat struct {
	Value string `json:"value"`
	Label string `json:"label"`
	Sub   string `json:"sub,omitempty"`
	Bad   bool   `json:"bad,omitempty"`
}

// pageRow is a row of a .list: what it is (name and lines under it), what
// it says on the right (a tag, a small value, buttons), and whether it
// opens something (a link).
type pageRow struct {
	Name  string    `json:"name"`
	Sub   string    `json:"sub,omitempty"`
	Mono  bool      `json:"mono,omitempty"`
	Tag   string    `json:"tag,omitempty"`
	TagOn string    `json:"tagOn,omitempty"` // good, bad, warn, mute
	Note  string    `json:"note,omitempty"`
	Text  string    `json:"text,omitempty"`
	Code  string    `json:"code,omitempty"` // a value in the page's code style
	Href  string    `json:"href,omitempty"` // the row's own link
	Acts  []pageAct `json:"acts,omitempty"`
	// Fields is the form's inputs (an empty list is a form of its tabs alone).
	Fields *[]pageField `json:"fields,omitempty"` // a form's row
}

// pageAct is a button (or the link's place) in a row: what it does — a
// route of the portal's — its label, and how it looks.
type pageAct struct {
	Label   string `json:"label"`
	Kind    string `json:"kind,omitempty"`   // primary, danger
	Href    string `json:"href,omitempty"`   // a link
	Post    string `json:"post,omitempty"`   // a form posted to this route
	Sub     string `json:"sub,omitempty"`    // its sub, posted with it
	Submit  bool   `json:"submit,omitempty"` // the form's own button
	Confirm string `json:"confirm,omitempty"`
}

// pageTable is a table of .led: its heads and its lines, each a list of
// cells (text, and its class: n for a number, bad for a failure).
type pageTable struct {
	Head []string   `json:"head"`
	Rows [][]string `json:"rows"`
	Bad  []bool     `json:"bad,omitempty"`
	Note string     `json:"note,omitempty"`
}

// pageForm is a form: its route, the person whose grant it is, its fields,
// and its buttons.
type pageForm struct {
	Post string `json:"post"`
	Get  bool   `json:"get,omitempty"` // a search: its fields in the address
	Sub  string `json:"sub,omitempty"`
	// Fields is the form's inputs (an empty list is a form of its tabs alone).
	Fields *[]pageField `json:"fields,omitempty"`
	Acts   []pageAct    `json:"acts,omitempty"`
	// Tabs is the form's line of tabs (the period open on) above its fields
	Tabs []pageAct `json:"tabs,omitempty"`
}

// pageField is one input of a form: its name, label, value, and kind.
type pageField struct {
	Name    string   `json:"name"`
	Label   string   `json:"label"`
	Value   string   `json:"value,omitempty"`
	Kind    string   `json:"kind,omitempty"` // text, textarea, number, select, hidden
	Options []string `json:"options,omitempty"`
	Note    string   `json:"note,omitempty"`
	Wide    bool     `json:"wide,omitempty"`
}

// pageItem is a line of a block's plain list (the models a key may use).
type pageItem struct {
	Name string `json:"name"`
	Sub  string `json:"sub,omitempty"`
}

// magpiePageView is the data in the form the page's script reads it: JSON,
// escaped for the script's own element.
func magpiePageView(d magpiePageData) string {
	if d.Open == "" && len(d.Pages) > 0 {
		d.Open = d.Pages[0].Key
	}
	// blocks' slices are nil when they draw nothing, in the script's words
	for i := range d.Blocks {
		if d.Blocks[i].Table != nil && d.Blocks[i].Table.Bad == nil {
			d.Blocks[i].Table.Bad = make([]bool, len(d.Blocks[i].Table.Rows))
		}
	}
	// JSON's own escaping is enough inside a script element but for one
	// spelling: a "</script" in a value would end it, so every "</" is
	// written <\/ (the same string to a script).
	b, _ := json.Marshal(d)
	return strings.ReplaceAll(string(b), "</", "<\\/")
}

// magpiePageHead is the head of a page in magpie's own frame, as magpie's
// page has it (internal/gui/assets/index.html): the stylesheets, the theme
// before the page paints, and the portal's data of it. Body carries
// magpie's own classes for the frame (side-nav), and its top line of
// views is dropped: a page of the portal's has the portal's.
func magpiePageHead(title, data, assets string) string {
	if assets == "" {
		assets = "/app.css"
	}
	return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + htmlEsc(title) + ` · magpie</title>
<link rel="icon" href="/favicon.ico" type="image/svg+xml">
<link rel="stylesheet" href="` + htmlEsc(assets) + `">
<link rel="stylesheet" href="/omarchy.css">
<link rel="stylesheet" href="/plugins.css">
<link rel="stylesheet" href="/context.css">
<link rel="stylesheet" href="/portal/console.css">
<!-- magpie's page's own order (index.html): its boot prefs, the theme
     before the page paints, then its scripts; i18n.js is magpie's words,
     kernel.js the plugin kernel the page's own pages need -->
<script src="/boot.js"></script>
<script src="/theme.js"></script>
<script src="/omarchy.js"></script>
<script src="/compat.js"></script>
<script src="/layout.js"></script>
<script src="/fonts.js"></script>
<script src="/i18n.js"></script>
<script id="oidc-page" type="application/json">` + data + `</script>
</head>
<body class="side-nav">
<!-- magpie's frame (app.js layoutNav's sidebar), its own elements: the
     sidebar of the portal's pages (#nav), then the header and the page -->
<aside class="sidebar" id="side">
<div class="side-top"><div class="brand"><span>magpie</span></div></div>
<div class="side-scroll" id="nav"></div>
<div class="side-foot"></div>
</aside>
<header class="top">
<div class="crumb" id="crumb"></div>
<h1 class="sr-only" id="pageTitle"></h1>
<div class="actions" id="topRight"></div>
</header>
<main class="view" id="view-oidc"></main>
<script src="/kernel.js"></script>
<script src="/portal/page.js"></script>
</body>
</html>
`
}

// pageRoute is a page of the portal's in magpie's frame: where it lives and
// what it names in the sidebar.
func pageRoute(href, key, label string) magpiePageRef {
	return magpiePageRef{Key: key, Label: label, Href: href, View: true}
}

// adminPages is an admin's sidebar: their console (magpie's page, every
// view of it), its key page, and the portal's pages — 门户管理 here, and
// the way out.
func adminPages() []magpiePageRef {
	return []magpiePageRef{
		{Key: "console", Label: "控制台", Href: "/"},
		{Key: "mine", Label: "我的密钥", Href: "/"},
		pageRoute("/admin", "admin", "门户管理"),
		{Key: "logout", Label: "退出登录", Href: "/logout"},
	}
}

// keyReadyPages is a person's sidebar once they have a key: their two pages,
// which are magpie's page's own (consolepage.go), and the exit.
func keyReadyPages() []magpiePageRef {
	return []magpiePageRef{
		pageRoute("/", "mine", "我的密钥"),
		pageRoute("/?view=oidc-usage", "oidc-usage", "用量"),
		{Key: "logout", Label: "退出登录", Href: "/logout"},
	}
}

// simplePages is a person's sidebar before they have a key, and an
// error's: the way back, and the exit.
func simplePages(href, key string) []magpiePageRef {
	return []magpiePageRef{
		pageRoute(href, key, "我的密钥"),
		{Key: "logout", Label: "退出登录", Href: "/logout"},
	}
}

// htmlEsc is text in HTML, attributes included.
func htmlEsc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

// queryOf is a page's query as the script reads it back (a form's or a
// tab's next address).
func queryOf(q url.Values, drop ...string) string {
	c := url.Values{}
	for k, v := range q {
		c[k] = v
	}
	for _, k := range drop {
		c.Del(k)
	}
	return c.Encode()
}
