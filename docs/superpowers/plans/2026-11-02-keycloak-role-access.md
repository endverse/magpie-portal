# Keycloak 角色内置化 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 门户角色改由 Keycloak 登录令牌决定(内置角色名 `magpie-super`/`magpie-operator`),oidc.yaml 删除全部管理员配置;operator 与 super 的控制台路由按最终路由表白名单拦截(正文/上下文只有 super 可看)。

**Architecture:** sidecar 从 ID token 的 claim(沿用 `group_claim` 路径,默认 `groups`)读出角色名,与写死在 Go 代码里的两个常量比对得出三档身份(user / operator / super)。反向代理按角色查白名单放行或拦截;注入脚本按角色裁剪导航和 routing 页的上下文区域。所有代码改动都在 `oidcsidecar/`,不碰 magpie 源码。

**Tech Stack:** Go 1.26(标准库 `golang.org/x/oauth2`+`oidc` 已引入)、现有 node DOM 存根测试框架、CDP 冒烟截图。

**工作目录:** `/Users/michael/code/github/magpie`,分支 `magpie-portal`。所有路径相对 `oidcsidecar/oidcportal/`。每完成一个任务运行 `go test -count=1 ./...`(在 `oidcsidecar/` 下)并提交。

**最终路由表(所有任务的依据):**

| 路由/API | user | operator | super |
|---|---|---|---|
| 自建页 我的密钥+用量(`/me` 页、`/key/*`、`/v1/magpie/me*`) | ✅ | ✅(keyPageAny 部分) | ✅ |
| `/api/providers*`、`/api/groups*`(路由组)、`/api/gateway`(配置)、`/api/masking*`、`/api/plugins*`、`/api/settings*`、`/api/usage`(概览) | ❌ | ✅ | ✅ |
| `/api/gateway/trace`、`/api/gateway/history`、`/api/gateway/session-titles`、`/api/gateway/call`、`/api/usage/requests/content`、`/api/context/text` | ❌ | ❌(正文/上下文,涉密) | ✅ |
| 密钥值类(`/api/caller-keys/copy-key` 等 `consoleBlocked` 其余项) | ❌ | ❌(所有人,永放) | ❌ |
| 门户管理 `/admin`、`/admin/*`、`/hooks/*` | ❌ | ✅ | ✅ |
| Langfuse 正文入口链接 | ❌ | ❌ | ✅ |
| 侧边栏 agents / sessions / library | ❌ | ❌(所有人隐藏) | ❌ |
| 静态资产(`/console/` 下 js/css/图标、`/wails/`) | — | ✅ GET | ✅ GET |

---

### Task 1: Identity 增加角色判定常量

**Files:**
- Modify: `oidcportal/oidc.go` (Identity struct, line 15-21 附近)
- Test: `oidcportal/oidc_test.go`(已存在,追加)

- [ ] **Step 1: 写失败测试**

在 `oidc_test.go` 追加(该文件已有 `TestIdentityInGroup` 风格的测试,跟随其样式):

```go
func TestIdentityRoles(t *testing.T) {
	id := Identity{Subject: "s", Groups: []string{"magpie-super", "/magpie-operator", "team-a"}}
	if !id.HasRole("magpie-super") {
		t.Fatal("magpie-super not seen")
	}
	if !id.HasRole("magpie-operator") {
		t.Fatal("magpie-operator not seen behind its leading slash")
	}
	if id.HasRole("magpie-none") {
		t.Fatal("an unheld role says held")
	}
	plain := Identity{Subject: "s", Groups: []string{"team-a"}}
	if plain.HasRole("magpie-super") || plain.HasRole("magpie-operator") {
		t.Fatal("a plain person reads as a role holder")
	}
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cd /Users/michael/code/github/magpie/oidcsidecar && go test -count=1 ./oidcportal/ -run TestIdentityRoles -v`
Expected: FAIL,`HasRole` 未定义

- [ ] **Step 3: 实现**

`oidc.go` 中,`InGroup` 方法旁加常量与方法:

```go
// The portal's built-in roles, held as groups in the identity's claim.
// Their names are fixed here, not in the config: whoever Keycloak says
// holds one, does.
const (
	RoleSuper    = "magpie-super"    // everything, bodies included
	RoleOperator = "magpie-operator" // the console's operations, no bodies
)

// HasRole says whether the identity holds the named built-in role, by the
// same reading InGroup uses (the provider's spelling, or slashless).
func (id Identity) HasRole(role string) bool { return id.InGroup(role) }
```

- [ ] **Step 4: 运行确认通过**

Run: `go test -count=1 ./oidcportal/ -run TestIdentityRoles -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add oidcsidecar/oidcportal/oidc.go oidcsidecar/oidcportal/oidc_test.go
git commit -m "oidcportal: built-in role names on the identity"
```

---

### Task 2: IsAdmin / IsSuperAdmin 改为只看令牌角色

**Files:**
- Modify: `oidcportal/config.go:418-429`(两个判定函数)、`config.go:69-82`(Config struct 字段注释)
- Modify: `oidcportal/config_test.go`(跟随现有用例样式)

- [ ] **Step 1: 改测试**

`config_test.go` 里现有 `TestIsAdmin`/`TestIsSuperAdmin` 一类用例(按 `Admins: []string{...}` 构造的)整体替换为角色判定用例:

```go
func TestRolesDecide(t *testing.T) {
	c := &Config{} // no admin fields at all
	super := Identity{Subject: "s", Groups: []string{"magpie-super"}}
	operator := Identity{Subject: "s", Groups: []string{"magpie-operator"}}
	plain := Identity{Subject: "s"}
	if !c.IsAdmin(super) || !c.IsSuperAdmin(super) {
		t.Fatal("magpie-super is not the super admin")
	}
	if !c.IsAdmin(operator) {
		t.Fatal("magpie-operator is not an admin")
	}
	if c.IsSuperAdmin(operator) {
		t.Fatal("magpie-operator reads as a super admin")
	}
	if c.IsAdmin(plain) || c.IsSuperAdmin(plain) {
		t.Fatal("a person with no role reads as an admin")
	}
}
```

再删掉(或改写掉)所有引用 `c.Admins`/`c.SuperAdmins`/`c.AdminGroups`/`c.SuperAdminGroups` 的旧用例与辅助函数——Task 3 会删字段,留着编译不过。

- [ ] **Step 2: 运行确认失败**

Run: `go test -count=1 ./oidcportal/ -run TestRolesDecide -v`
Expected: PASS 可能直接通过(&Config{} 现在也拒绝),旧用例仍在;先跑全量:

Run: `go test -count=1 ./oidcportal/`
Expected: 现状 PASS(此步只为确认基线)

- [ ] **Step 3: 实现判定替换**

`config.go:418-429` 两个函数体替换:

```go
// IsAdmin says whether the identity may open the admin page: the token
// holds magpie-super or magpie-operator. The config says nothing of it —
// roles live in the provider, their names here.
func (c *Config) IsAdmin(id Identity) bool {
	return c.IsSuperAdmin(id) || id.HasRole(RoleOperator)
}

// IsSuperAdmin says whether the identity may do what only a super admin
// may, such as read a request's and reply's contents.
func (c *Config) IsSuperAdmin(id Identity) bool {
	return id.HasRole(RoleSuper)
}
```

同时检查 `config.go:459` 附近引用 `c.Admins`/`c.SuperAdmins` 的函数(如 `namedPerson` 调用处,若有按邮箱豁免的逻辑)一并删除;`Config` struct 的 `Admins`/`AdminGroups`/`SuperAdmins`/`SuperAdminGroups` 字段及 yaml 键在 Task 3 删。

- [ ] **Step 4: 全量测试**

Run: `go test -count=1 ./...`
Expected: 除引用已废弃字段的用例外全部 PASS(下一任务清理);若有旧用例编译错误,把它们删除或改写为角色用例后再跑,直至 PASS。

- [ ] **Step 5: Commit**

```bash
git add oidcsidecar/oidcportal/config.go oidcsidecar/oidcportal/config_test.go
git commit -m "oidcportal: admin decisions read the token's roles, not the config"
```

---

### Task 3: 配置删除管理员字段

**Files:**
- Modify: `oidcportal/config.go`(Config struct 删 `Admins`/`AdminGroups`/`SuperAdmins`/`SuperAdminGroups`,行 69-82 附近;删 `named`/`namedPerson` 中只为管理员服务的分支)
- Modify: `oidcportal/config_test.go`
- Modify: `/Users/michael/orca/magpie/oidc.yaml`(部署侧,删 `admins:`/`super_admins:` 两行)

- [ ] **Step 1: 写失败测试**

`config_test.go` 追加:

```go
func TestConfigHasNoAdminFields(t *testing.T) {
	src := []byte("issuer: http://x\nclient_id: c\nredirect_url: http://x/cb\nlisten: :0\n" +
		"admins: [a@x]\nsuper_admins: [b@x]\n")
	if _, err := LoadConfigBytes(src); err != nil {
		t.Fatalf("a config with the retired fields loads, ignored: %v", err)
	}
}
```

(若 `LoadConfigBytes` 不存在,看 config_test.go 现有加载辅助——现有测试都从字节或临时文件加载,用同一个辅助。)

- [ ] **Step 2: 运行**

Run: `go test -count=1 ./oidcportal/ -run TestConfigHasNoAdminFields -v`
Expected: 可能已 PASS(未导出字段 yaml 忽略);基线确认,继续。

- [ ] **Step 3: 删字段**

Config struct 删除四个字段及其注释;全文搜索 `Admins`、`SuperAdmins`、`AdminGroups`、`SuperAdminGroups`、`namedPerson`,删除残留引用(含 `normalizeGroups` 无关保持不动)。若某处(server.go / consoleboot.go)还有基于邮箱的豁免逻辑引用它们,该处已在 Task 2 覆盖,删除即可。

- [ ] **Step 4: 全量测试 + go vet**

Run: `go test -count=1 ./... && go vet ./...`
Expected: PASS,无 vet 告警

- [ ] **Step 5: 更新部署配置并提交**

`/Users/michael/orca/magpie/oidc.yaml` 删除:

```yaml
admins: [magpie-alice@example.com]
# Super admins may open the console's plugin frames; key values and request
# and response bodies stay closed to them too. Bodies are read in Langfuse.
super_admins: [magpie-alice@example.com]
```

```bash
git add oidcsidecar/oidcportal/config.go oidcsidecar/oidcportal/config_test.go
git commit -m "oidcportal: the config no longer names admins"
```

---

### Task 4: 代理白名单改为三档(operator / super / 所有人禁止)

**Files:**
- Modify: `oidcportal/console.go:352-482`(`consoleAllowed`、`keyPageRoute`、`consoleBlocked`、`ordinaryConsoleAllowed`)
- Test: `oidcportal/console_test.go`

- [ ] **Step 1: 写失败测试**

`console_test.go` 追加(跟随现有表驱动样式):

```go
func TestConsoleAllowedByRole(t *testing.T) {
	const (
		op  = "operator"
		sup = "super"
	)
	cases := []struct {
		role   string
		path   string
		method string
		want   bool
	}{
		// operator 的运营面
		{op, "/api/providers", "GET", true},
		{op, "/api/providers", "POST", true},
		{op, "/api/groups", "GET", true},
		{op, "/api/gateway", "GET", true},
		{op, "/api/usage", "GET", true},
		{op, "/api/masking/records", "GET", true},
		{op, "/api/plugins", "GET", true},
		{op, "/api/settings", "GET", true},
		{op, "/api/set", "POST", true},
		// routing 页的上下文,涉密:operator 不行,super 行
		{op, "/api/gateway/trace", "GET", false},
		{op, "/api/gateway/history", "GET", false},
		{op, "/api/gateway/session-titles", "POST", false},
		{op, "/api/gateway/call", "GET", false},
		{op, "/api/usage/requests/content", "GET", false},
		{op, "/api/context/text", "GET", false},
		{sup, "/api/gateway/trace", "GET", true},
		{sup, "/api/gateway/history", "GET", true},
		{sup, "/api/gateway/session-titles", "POST", true},
		{sup, "/api/gateway/call", "GET", true},
		{sup, "/api/usage/requests/content", "GET", true},
		{sup, "/api/context/text", "GET", true},
		// 没人能看的:密钥值与档案
		{sup, "/api/caller-keys/copy-key", "POST", false},
		{sup, "/api/sessions/one", "GET", false},
		{op, "/api/caller-keys/copy-key", "POST", false},
		// operator 不看业务面
		{op, "/api/library", "GET", false},
	}
	for _, c := range cases {
		super := c.role == sup
		if got := consoleAllowed(super, c.path, c.method, ""); got != c.want {
			t.Errorf("%s %s %s: got %v want %v", c.role, c.method, c.path, got, c.want)
		}
	}
}
```

若现有测试引用 `ordinaryConsoleAllowed` 直接断言 library 放行,同步改写(删除 library 用例)。

- [ ] **Step 2: 运行确认失败**

Run: `go test -count=1 ./oidcportal/ -run TestConsoleAllowedByRole -v`
Expected: FAIL(trace/history/plugins 等现状不符)

- [ ] **Step 3: 实现白名单重构**

`console.go` 中:

(a) `consoleAllowed(super bool, …)` 签名不变(super 已由 `IsSuperAdmin` 传入;operator 与 super 都已过 `IsAdmin` 门,见 ServeHTTP:170)。

(b) `consoleBlocked` 拆为两层——**所有人禁止**(密钥值、档案、签名等)与**涉密**(正文/上下文,super 放行):

```go
// consoleBlocked names the answers refused for every role: gateway keys'
// values, session archives, the deployment's own secrets. A super admin
// reads bodies and context, but never these.
func consoleBlocked(path string) bool {
	switch path {
	case "/api/caller-keys/copy-key",
		"/api/caller-keys/add-key",
		"/api/caller-keys/rotate-key",
		"/api/gateway/held/reveal",
		"/api/library/reveal",
		"/api/masking/value",
		"/api/plugin-pages/read",
		"/api/web-page",
		"/api/settings/search-key",
		"/api/settings/archive",
		"/api/config/repair":
		return true
	}
	for _, prefix := range []string{
		"/api/archive",
		"/api/backup/",
		"/api/davsync/",
		"/api/sessions/transcript",
		"/api/sessions/one",
		"/api/sessions/markdown",
		"/api/sessions/export",
		"/api/sessions/reads",
		"/api/keys/",
		"/api/import/",
		"/api/dev/",
	} {
		if path == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// confidential names the request's and reply's own words — bodies and the
// context they ran in. Operator stops here; a super admin reads on.
func confidential(path string) bool {
	switch path {
	case "/api/gateway/call",         // request and response bodies
		"/api/gateway/trace",         // the routing page's live requests
		"/api/gateway/history",       // the routing page's per-day requests
		"/api/gateway/session-titles", // sessions behind the routing rows
		"/api/usage/requests/content",
		"/api/context/text":
		return true
	}
	return false
}
```

(c) `consoleAllowed` 中,`if super { return true }` 改为:

```go
	if super {
		return !consoleBlocked(path)
	}
```

(d) `ordinaryConsoleAllowed` 改名 `operatorAllowed` 并调整:删掉 library 两行;加 plugins、routing 页所需的组与路由组写接口(现状 `/api/groups` 已放行,确认 `/api/plugins` 及其子路径加入);usage 概览保留但涉密路径已在 super 分支前被 `confidential` 拦截——在函数开头加:

```go
// operatorAllowed is the operations face of the console: providers,
// routing groups, the gateway, usage overview, masking, plugins and
// settings. The request's own words are not here: confidential() already
// stopped them.
func operatorAllowed(path, method string) bool {
	get := method == http.MethodGet || method == http.MethodHead
	switch {
	case path == "/api/state", path == "/api/upstream", path == "/api/lanes",
		path == "/api/model-speeds", path == "/api/update",
		path == "/api/notices", path == "/api/whatsnew", path == "/api/fonts":
		return get
	case strings.HasPrefix(path, "/api/icons/"):
		return get
	case path == "/api/set":
		return method == http.MethodPost
	case path == "/api/providers", strings.HasPrefix(path, "/api/providers/"),
		strings.HasPrefix(path, "/api/provider/"):
		return true
	case path == "/api/groups", strings.HasPrefix(path, "/api/groups/"):
		return true
	case path == "/api/gateway": // the gateway's own settings; trace/history are confidential
		return true
	case path == "/api/gateway/route":
		return method == http.MethodPost
	case path == "/api/caller-keys", strings.HasPrefix(path, "/api/caller-keys/"):
		return true
	case path == "/api/usage", strings.HasPrefix(path, "/api/usage/"):
		return true
	case path == "/api/masking", strings.HasPrefix(path, "/api/masking/"):
		return true
	case path == "/api/plugins", strings.HasPrefix(path, "/api/plugins/"),
		path == "/api/plugin-panels":
		return true
	case path == "/api/settings", strings.HasPrefix(path, "/api/settings/"):
		return true
	}
	return false
}
```

并在 `consoleAllowed` 的非 super 分支改为:

```go
	if confidential(path) {
		return false // the request's own words: a super admin's only
	}
	return operatorAllowed(path, method)
```

- [ ] **Step 4: 运行确认通过**

Run: `go test -count=1 ./oidcportal/ -run TestConsoleAllowedByRole -v && go test -count=1 ./...`
Expected: PASS(其余测试如引用旧名 `ordinaryConsoleAllowed`,改名后同步)

- [ ] **Step 5: Commit**

```bash
git add oidcsidecar/oidcportal/console.go oidcsidecar/oidcportal/console_test.go
git commit -m "oidcportal: the console's allowlist by role, bodies a super admin's"
```

---

### Task 5: 前端按角色裁剪导航与 routing 页

**Files:**
- Modify: `oidcportal/consoleboot.go:66-90`(roleScript 传角色)、`consoleboot.go` person/admin 分支
- Modify: `oidcportal/consolepage.go`(adminPre 的脚本,nav 裁剪段)
- Modify: `oidcportal/consolecss.go`(角色 CSS)
- Test: `oidcportal/inline_test.go`

- [ ] **Step 1: 写失败测试**

`inline_test.go` 追加(复用 `personRunner` 的 mk 存根,新写一个 adminRunner 或在现有 admin 用例上扩展;此处在 `TestTheFramedPagesScriptRuns` 之外加):

```go
// An admin's script takes the page's nav down to the role's pages: the
// Work group (agents, sessions, library) is out for every admin, and the
// document's class says which role reads it.
func TestAnAdminsNavMatchesTheirRole(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	cmd := exec.Command(node, "-e", adminRunner) // below, beside personRunner
	cmd.Stdin = strings.NewReader(scriptCode(adminPre(Identity{
		Email: "boss@example.com", Roles: []string{"magpie-operator"},
	})))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("an operator's nav: %v\n%s", err, out)
	}
}
```

`adminRunner` 仿 `personRunner`:构造 `#nav` 含 `button[data-view]` 为 agents/sessions/library/providers/routing/gateway/usage/masking/plugins,`document.documentElement` 为带 `classList` 的存根;断言跑完后 agents/sessions/library 三个按钮被移除,`documentElement.className` 含 `oidc-operator`。

- [ ] **Step 2: 运行确认失败**

Run: `go test -count=1 ./oidcportal/ -run TestAnAdminsNavMatchesTheirRole -v`
Expected: FAIL(Identity 无 Roles 字段、adminRunner 未写齐——先把 adminRunner 写完整再看报错)

- [ ] **Step 3: 实现**

(a) `oidc.go` 的 `Identity` 加字段(会话 cookie 里的 JSON 随之携带;旧 cookie 无此字段 = 无角色 = user,重新登录即得):

```go
type Identity struct {
	Subject  string   `json:"subject"`
	Email    string   `json:"email,omitempty"`
	Name     string   `json:"name,omitempty"`
	Username string   `json:"username,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}
```

保持不变——角色就是 Groups 里的名字(`HasRole` 已在 Groups 上读),无新字段。

(b) `consoleboot.go` roleScript 换为按角色置类:

```go
// roleScript says whose console this is, from the page's first script:
// the class names the role, and the page's CSS prunes the nav by it.
const roleScript = "document.addEventListener('DOMContentLoaded',function(){setTimeout(function(){var r=window.oidcPerson&&(window.oidcPerson.super?'oidc-super':window.oidcPerson.admin?'oidc-operator':'oidc-person');if(r)document.documentElement.className+=' '+r},300)});\n"
```

`consoleboot.go` 的 `serveBoot` 中 `if f.cfg.IsAdmin(id) { extra["admin"] = true }` 后加:

```go
	if f.cfg.IsSuperAdmin(id) {
		extra["super"] = true
	}
```

(c) `consolepage.go` adminPre 的脚本里(nav 按钮 `mark()` 段之后)加裁剪:删掉三个 Work 页按钮——

```js
// the Work pages are this deployment's machine's own: no role of the
// portal's reads them
["agents","sessions","library"].forEach(function(v){var b=side.querySelector('button[data-view="'+v+'"]');if(b)b.remove();});
```

(d) `consolecss.go` 追加:

```css
/* the routing page's live requests and their bodies: a super admin's */
html.oidc-operator #rt, html.oidc-operator #rtMore { display:none }
/* the Langfuse jump: bodies are a super admin's */
html.oidc-operator a[href*="langfuse"] { display:none }
```

- [ ] **Step 4: 全量测试**

Run: `go test -count=1 ./...`
Expected: PASS(页面脚本解析测试继续跑在改过的脚本上)

- [ ] **Step 5: Commit**

```bash
git add oidcsidecar/oidcportal/consoleboot.go oidcsidecar/oidcportal/consolepage.go oidcsidecar/oidcportal/consolecss.go oidcsidecar/oidcportal/inline_test.go
git commit -m "oidcportal: the page prunes its nav and its bodies by role"
```

---

### Task 6: 门户管理页对 operator 开放(现有 /admin 门改为 IsAdmin 已天然覆盖,回归确认)

**Files:**
- Modify: 无代码——`server.go:311/477/547/1256` 的门都是 `IsAdmin`,Task 2 后 operator 已在内
- Test: `oidcportal/server_test.go`(或现有 admin 测试所在文件)

- [ ] **Step 1: 写失败测试**

```go
func TestAdminPageForOperator(t *testing.T) {
	// follow the existing admin-page test's setup; sign in with an
	// identity whose Groups hold magpie-operator only
	// GET /admin → 200 and the page's own 门户管理 markup
}
```

(按现有 admin 测试的请求辅助写全;若现有测试已参数化身份组,加一行 operator 用例即可。)

- [ ] **Step 2: 运行确认现状**

Run: `go test -count=1 ./oidcportal/ -run TestAdminPageForOperator -v`
Expected: Task 2 之后应已 PASS——此任务是**回归确认**,不是新逻辑。若 FAIL,检查 server.go 各门是否有绕过 `IsAdmin` 的 `IsSuperAdmin` 直调并改正。

- [ ] **Step 3: 全量 + Commit**

```bash
go test -count=1 ./... && go vet ./...
git add oidcsidecar/oidcportal/
git commit -m "oidcportal: the admin page answers an operator too (regression)"
```

---

### Task 7: Keycloak 侧配置 + 部署重建

**Files:**
- Modify: `/Users/michael/orca/magpie/oidc.yaml`(Task 3 已删 admins)
- Keycloak:管理台或 kcadm 建 realm role 并分配

- [ ] **Step 1: Keycloak 建角色**

用 kcadm(管理员账号密码在 `keycloak/.env`):

```bash
KCADS=$(docker run --rm --network orca_magpie quay.io/keycloak/keycloak:26 kcadm.sh 2>/dev/null || true)
# 或直接用管理台 http://192.168.100.220:8180/admin/ :
#   Realm roles → Create role → magpie-super
#   Realm roles → Create role → magpie-operator
#   Users → magpie-alice → Role mapping → assign magpie-super
```

- [ ] **Step 2: 确认角色进令牌**

```bash
curl -s http://192.168.100.220:8180/realms/bjwgby/protocol/openid-connect/token \
  -d grant_type=password -d client_id=magpie.local -d scope=openid \
  -d username=magpie-alice@example.com -d password='<管理员密码>' | jq -r .access_token | cut -d. -f2 | base64 -d 2>/dev/null | jq .realm_access.roles
```

Expected: 含 `magpie-super`。若 realm 用 `groups` 而非 roles,把角色加为 Group 属性并在 Keycloak client mapper 里把组映射进令牌的 `groups` claim(与 `group_claim: groups` 对齐)。

- [ ] **Step 3: 重建并重启 sidecar**

```bash
cd /Users/michael/orca/magpie
DOCKER_BUILDKIT=0 docker compose build magpie-oidc 2>&1 | tail -2
docker compose up -d --force-recreate --pull never magpie-oidc
```

- [ ] **Step 4: 三角色冒烟(CDP,复用 /tmp/pw/flow.mjs)**

- super(magpie-alice@example.com):/admin 200、控制台 routing 页上下文区可见
- operator(给 magpie-bob@example.com 临时加 magpie-operator 角色后):/admin 200、routing 页 `#rt` 隐藏、curl 直打 `/api/gateway/trace` 得 403
- user(magpie-carol@example.com,无角色):/ 仍是我的密钥+用量

- [ ] **Step 5: Commit(若有脚本/配置改动)**

```bash
git add -A && git commit -m "deploy: roles from Keycloak, config without admin names"
```

---

### Task 8: 设计文档同步最终路由表

**Files:**
- Modify: `docs/superpowers/specs/2026-11-02-keycloak-role-access-design.md`

- [ ] **Step 1: 把最终路由表(本计划开头的表)替换文档中"角色"一节的三行表,并在"权限执行"一节补一句:涉密路径(`confidential()`)super 放行、operator 拦截,密钥值类对所有人关闭。**

- [ ] **Step 2: 中文同步到 Orca 工作区副本**

```bash
cp docs/superpowers/specs/2026-11-02-keycloak-role-access-design.md /Users/michael/orca/magpie/2026-11-02-keycloak-role-access-design.md
```

- [ ] **Step 3: Commit + Push**

```bash
git add docs/superpowers/specs/2026-11-02-keycloak-role-access-design.md
git commit -m "docs: the final route table by role"
git push portal magpie-portal
```
