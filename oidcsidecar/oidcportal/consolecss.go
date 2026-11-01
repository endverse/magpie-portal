package oidcportal

// consoleCSS is the portal's console.css, served to magpie's page: what an
// ordinary person's console puts in the page's place (personCSS,
// consolepage.go), and what the portal's own pages in magpie's frame
// (magpiepage.go) need — their sidebar's rows, their tables and forms, as
// the page's own views are drawn.
const consoleCSS = personCSS + roleCSS + framedCSS

// roleCSS is what the page's role leaves out of an admin's console. The
// page hides what the server refuses — this is cosmetic; the proxy is the
// check. An operator loses the routing page's live requests and the bodies
// around them. A jump to Langfuse, when the console grows one, is a super
// admin's too.
const roleCSS = `
html.oidc-operator #rt, html.oidc-operator #rtMore { display: none; }
`

// framedCSS is the framed pages' own: their sidebar rows are links (the
// page draws <a>, its nav buttons are <button>), their forms, and their
// tables' wrap, in the page's own measures.
const framedCSS = `
#nav a { display: flex; align-items: center; justify-content: flex-start; gap: 9px; width: 100%; height: 30px; padding: 0 8px; border-radius: 7px; font-size: 13px; color: var(--fg-2); text-align: left; white-space: nowrap; text-decoration: none; }
#nav a > span { min-width: 0; overflow: hidden; text-overflow: ellipsis; }
#nav a:hover:not(.on) { background: var(--pill); color: var(--fg); }
#nav a.on { background: var(--card); color: var(--fg); box-shadow: var(--seg-edge); font-weight: 500; }
#nav a .nav-ic { display: block; flex: none; color: var(--muted); }
.side-foot .oidc-who { padding: 8px 10px 2px; font-size: 11px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.oidc-led { background: var(--card); border: 1px solid var(--line); border-radius: 12px; overflow: hidden; margin: 4px 0 12px; }
.oidc-led .led-none { padding: 14px; margin: 0; color: var(--muted); text-align: center; font-size: 12px; }
.oidc-acts { display: flex; align-items: center; gap: 6px; margin-left: auto; flex: none; }
.oidc-acts button.text { font-size: 12px; height: 24px; padding: 0 9px; border-radius: 6px; background: var(--pill); border: 0; color: var(--fg-2); cursor: pointer; }
.oidc-acts button.text:hover { color: var(--fg); background: var(--card-2, var(--pill)); }
.oidc-acts button.text.danger { color: var(--red); }
.oidc-acts button.text.danger:hover { background: var(--red-soft); color: var(--red); }
.oidc-acts button.text.busy { color: var(--amber); }
.oidc-acts button.text[disabled] { opacity: .5; cursor: default; }
.oidc-form { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 12px 14px; display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-end; margin: 4px 0 12px; }
.oidc-form .oidc-field { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
.oidc-form .oidc-field > span { font-size: 11px; color: var(--muted); }
.oidc-form .oidc-field input, .oidc-form .oidc-field select { font: inherit; font-size: 12.5px; color: var(--fg); background: var(--card); border: 1px solid var(--line); border-radius: 7px; padding: 4px 8px; max-width: 260px; min-width: 0; }
.oidc-form .oidc-field input:focus, .oidc-form .oidc-field select:focus { outline: none; border-color: var(--accent); }
#view-oidc .oidc-page { display: flex; flex-direction: column; min-height: 0; padding: 10px 14px 20px; max-width: 980px; }
#view-oidc .oidc-head { padding: 2px 0 6px; }
#view-oidc .row-head { margin: 14px 0 6px; padding: 0 2px; }
#view-oidc .row-head .label { font-size: 12.5px; font-weight: 500; color: var(--fg-2); }
#view-oidc p.oidc-note { margin: 6px 0 12px; padding: 8px 12px; border-radius: 9px; font-size: 12.5px; background: var(--accent-soft, var(--pill)); color: var(--fg); }
#view-oidc table.led .when { white-space: nowrap; }
#view-oidc .oidc-tabs { margin: 4px 0 6px; }
`
