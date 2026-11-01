# 门户角色权限内置化 — 设计文档

日期:2026-11-02
状态:已实现(实现记录见下)

## 问题

现在门户的管理员判定来自配置文件(oidc.yaml 里的 `admins`、`super_admins` 及其 `*_groups` 变体)。任何能改这个文件的人都能把自己变成管理员。而且"项目维护者"(operator)这个角色根本不存在:现在一个人要么是完整管理员,要么是普通用户。

部署方希望角色由 Keycloak 管理,而不是由门户读取的文件管理:给某人分配角色在 Keycloak 管理台里做,sidecar 只读登录令牌里的内容。oidc.yaml 里没有任何角色配置。

## 角色(内置,角色名不可配置)

两个写死在代码里的角色名:

| Keycloak 角色 | 门户身份 | 能看到什么 |
|---|---|---|
| `magpie-super` | 超级维护者 | operator 的一切 **外加** 门户管理(人员、额度、审批)和涉密正文 |
| `magpie-operator` | 项目维护者 | magpie 控制台的 供应商、路由、网关、用量(仅概览)、设置、脱敏、扩展,以及门户管理 |
| (两者都没有) | 普通用户 | 自己的密钥页(我的密钥)和自己的用量(用量) |

一个人同时持有两个角色就是超级维护者。角色是 Keycloak 的 realm 角色;令牌通过 claim 携带它们(默认路径 `realm_access.roles`,仍可用现有 `group_claim` 设置覆盖——该配置键保留原名称和行为)。

## 最终路由表

控制台页面的可见性(前端)与 API 的放行(后端代理)一致:

| 页面/能力 | 普通用户 | 项目维护者 | 超级维护者 |
|---|---|---|---|
| 我的密钥(自建) | ✓ | ✓ | ✓ |
| 用量(自建,自己的数据) | ✓ | ✓ | ✓ |
| Agent / Sessions / Library | ✗ | ✗ | ✗ |
| 供应商 | ✗ | ✓ | ✓ |
| 路由(不含上下文/正文面板) | ✗ | ✓ | ✓ |
| 网关 | ✗ | ✓ | ✓ |
| 用量(控制台,仅概览) | ✗ | ✓ | ✓ |
| 脱敏、扩展 | ✗ | ✓ | ✓ |
| 设置 | ✗ | ✓ | ✓ |
| 门户管理 | ✗ | ✓ | ✓ |
| 路由的请求正文、用量明细正文、上下文 | ✗ | ✗ | ✓(去 Langfuse 排障) |

后端代理的常量分组(oidcportal/console.go):

- **consoleBlocked** — 任何角色都拿不到:gateway key 的完整值、归档/备份、部署密钥、正文捕获开关等。
- **confidential** — 只有超级维护者:`/api/gateway/call`、`/api/gateway/trace`、`/api/gateway/history`、`/api/gateway/session-titles`、`/api/usage/requests/content`、`/api/context/text`。
- **operatorAllowed** — 项目维护者以上:providers、groups、`/api/gateway` + 路由 POST、用量概览(heatmap/deleted/token)、masking、plugins、settings、`/api/set` POST、caller-keys 列表与 models(只读)、以及若干状态类 GET。
- 普通用户自己的数据路由(`/api/usage/requests` 等)由门户自己的 fetch 以该人自己的 key 代答,不放宽 operatorAllowed。

## 权限执行:按角色过滤路由

magpie 控制台是一组页面路由(hash 路由渲染 `view-*`,加上它们调用的后端 API)。sidecar 1:1 地提供 magpie 的页面,并在两层按角色过滤:

1. **前端**——注入的角色脚本移除角色白名单之外的导航项和视图。这只影响体验。
2. **后端**——sidecar 的反向代理拒绝白名单之外的路由/API 请求(返回 404 或无权限页),伪造的请求到不了 magpie。这才是真正的权限边界。

白名单是 sidecar Go 代码里的常量。给角色加页面意味着改代码,不是改配置。

## 配置变更

- oidc.yaml 删除 `admins`、`admin_groups`、`super_admins`、`super_admin_groups`。`IsAdmin`/`IsSuperAdmin` 只由令牌中的角色决定。
- 配置里其他一切(issuer、client_id、redirect_url、groups → 模型映射、额度、按人覆盖)保持不变。额度和模型授权仍是 sidecar 自己的数据,在管理页维护。

## 数据说明

- 面向用户的用量页继续把 magpie 的用量数据过滤成该人自己 key 的数据(key 重置后 key id 不变,历史用量连续)。
- operator 只看到用量概览——没有按人的明细。超级维护者保留完整的门户管理。

## 实现中的补充决策

- **先审批后给角色的人也能进来**:管理员可能在一个人还没有角色时批准过他(批准时没有任何可授予的模型)。这种人一旦持有角色再登录,登录时把批准时的 groups 移到 `grantGroups` 存根,换成这次登录的 groups,授权经由角色解析;存根在本人 groups 解析不出模型时兜底。`ProvidersFor` 不再在 groups 没点名任何供应商时回落到 `default_providers`。
- **超级角色不受门户审批左右**:持有 `magpie-super` 的人,门户的"拒绝/停用"(页面和审批 hook)都直接拒绝执行并提示去 Keycloak 收回角色;门户批准与否不改变角色权限。"启用"则把这种 standing 恢复为可解析的 key。
- 测试:`TestAnOperatorApprovedEarlierStillGetsIn`(先审批后给角色)、既有的 `TestRejectedSuperAdminIsNotAdopted`、路由表测试等覆盖上述行为。

## 测试

- 配置测试:旧的管理员字段已删除;没有这些字段的配置能加载。
- 角色测试:令牌 claim → 角色判定,包括同时有两个角色、没有角色的情况,以及点分 claim 路径。
- 路由测试:每个角色,白名单内的代理路由放行,其余在服务端拒绝;注入脚本的导航与白名单一致。
- 现有的页面脚本解析测试在改动的脚本上继续运行。
