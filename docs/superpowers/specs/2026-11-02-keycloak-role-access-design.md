# Role-based access built into the sidecar — design

Date: 2026-11-02
Status: approved in conversation, awaiting spec review

## Problem

The portal's admin rights today come from the config file (`admins`,
`super_admins`, their `*_groups` variants in oidc.yaml). Anyone who can edit
that file grants themselves admin. The operator (project maintainer) role
does not exist at all: today a person is either a full admin or a plain user.

The deployment wants roles to live in Keycloak, not in a file the portal
reads: assigning a role to a person happens in the Keycloak admin console,
and the sidecar only reads what the login token says. No role configuration
in oidc.yaml.

## Roles (built-in, names not configurable)

Two role names, fixed in code:

| Keycloak role        | Portal identity    | What they see |
|----------------------|--------------------|---------------|
| `magpie-super`       | super maintainer   | everything an operator sees **plus** 门户管理 (people, budgets, approvals) |
| `magpie-operator`    | project operator   | magpie console's 供应商, 路由, 网关, 用量 (overview only), 设置 |
| (neither)            | user               | own key page (我的密钥) and own usage (用量) — already built |

A person holding both roles is a super maintainer. Roles are realm roles in
Keycloak; the token carries them in a claim (default path
`realm_access.roles`, still overridable by the existing `group_claim`
setting — that key keeps its name and behavior).

## Enforcement: route filtering by role

Magpie's console is a set of page routes (hash routes rendering `view-*`
plus the backend APIs they call). The sidecar serves magpie's page 1:1 and
filters by role at two layers:

1. **Frontend** — the injected role script removes nav entries and views
   outside the role's whitelist. Experience only.
2. **Backend** — the sidecar's reverse proxy rejects requests for routes /
   APIs outside the role's whitelist (404 or a permission page), so a
   crafted request cannot reach magpie. This is the actual permission
   boundary.

Whitelists are constants in the sidecar's Go code. Adding a page to a role
means changing code, not config.

## Config changes

- oidc.yaml loses `admins`, `admin_groups`, `super_admins`,
  `super_admin_groups`. `IsAdmin`/`IsSuperAdmin` are answered by the token's
  roles only.
- Everything else in the config (issuer, client_id, redirect_url, groups →
  model mapping, budgets, per-person overrides) stays as is. Budgets and
  model grants are still sidecar data, managed on the admin page.

## Data notes

- The user-facing usage page keeps filtering magpie's usage data to the
  person's own keys (key id survives a key reset, so history is continuous).
- Operators see usage overview only — no per-person detail. The super
  maintainer keeps the full 门户管理.

## Testing

- Config tests: old admin fields gone; a config without them loads.
- Role tests: token claims → role decision, including both-roles and
  no-roles cases, and the dotted claim path.
- Route tests: per role, whitelisted proxy routes pass, others are rejected
  server-side; the injected script's nav matches the whitelist.
- The existing page-script parse tests keep running on the changed script.
