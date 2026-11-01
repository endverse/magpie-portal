# OIDC gateway keys

The OIDC sidecar, `oidcsidecar/cmd/magpie-oidc` over
`oidcsidecar/oidcportal`, signs a person in at an OpenID Connect provider
and keeps one magpie gateway key for them, held to the providers their
groups name. A user in Keycloak's
`team-claude` group can be given a key that may use only that provider; a
user in `team-claude` and `team-openai` gets both, and no other.

## Why a sidecar, not a plugin

A plugin cannot do this today, and the reason is the caller's identity:

- The gateway's middleware and request hooks are never told which gateway
  key a request came with. `gwmw.Info` (`internal/gwmw/gwmw.go`) and
  `plugin.GatewayContext` (`internal/plugin/gateway.go`) carry the protocol,
  model, path and origin, never the authorization header; the request-hook
  reference says so in
  [gateway-request-hooks.md](../../docs/subsystems/gateway-request-hooks.md).
- The built-in plugin runtime's extension points are observer, router
  strategy, middleware, tool and budget
  ([plugin-runtime.md](../../docs/subsystems/plugin-runtime.md)); none runs before the gateway
  authenticates a key, so none can decide who the caller is.
- A page plugin cannot reach the network (`connect-src 'none'`), and the
  gateway's key store is a file beside magpie's config, not a plugin API.

So the portal is a separate program that imports `internal/access` directly.
It must run on the same computer and as the same user as magpie: that is
what makes `access.Update` write the store the gateway reads
(`access.Path()`). Pointing it at a magpie on another host would write the
wrong store, not a remote one. In the Docker image it would need magpie's
`/config` volume and uid; the image does not build or run it yet.

## Key scoping is magpie's own

A gateway key already carries its scope: `Key.Models` names
`<provider>/<model>`, `<provider>/*` or `group/<id>`; `Key.Accounts` names
accounts; `Key.Limit` is its budget (`internal/access/models.go`,
`internal/access/limit.go`). The gateway enforces them before it picks a
provider (`keyHolds` in `internal/gateway/key_models.go`). The sidecar does
not add a second authorization layer; it writes these fields.

The sidecar needs no change to magpie's source. `add-key` makes a key with
a name, a value and a read-only flag; the sidecar then sets its models,
budget and quotas with `models-key`, `limit-key` and `quotas-key`, and only
then makes it usable with `access-key`. Because the key is read-only until
its scope is in place, an interrupted provision leaves a key that can read
stats but call no model, never an unrestricted one; the next sign-in finds
it by name and finishes it.

A key naming `group/<id>` is allowed every member of that routing group; a
key naming `a/*` is not enough to allow a group that also contains `b`. The
sidecar therefore writes provider patterns, never group names, so a group's
membership cannot silently widen a user's key.

## Configuration

```yaml
issuer: https://keycloak.example.com/realms/main
client_id: magpie
client_secret: …            # omit for a public client with PKCE
redirect_url: https://magpie.example.com/callback
listen: 127.0.0.1:3440

# magpie's own web console, served at /console/ behind this portal's
# sign-in. Keep the console port unpublished: this is the only way in.
# console_web_key defaults to $MAGPIE_WEB_KEY, the same key magpie runs with.
console_url: http://magpie:3430
# console_web_key: …
# console_cookie: magpie_web_3430   # derived from the URL's port

# OIDC group (Keycloak group path, leading slash optional) -> what its
# members' keys may use. A bare provider is short for "<provider>/*".
groups:
  team-claude: [anthropic]
  team-openai: [openai]
  team-everything: [anthropic, openai, "google/*"]

# Users whose groups match none. Empty turns them away with no key.
default_providers: []

# Who may open /admin is not set here: roles live in the identity provider
# (Keycloak), as the realm roles magpie-operator and magpie-super in the
# token's groups claim. magpie-super may also open the console's plugin
# frames; key values and request/response bodies stay closed to both and are
# read in Langfuse. There is no admin list in this file.

# Off by default: a person signs in, applies, and an admin assigns their
# models and budget. On grants what groups:/users: say at first sign-in,
# the portal's behavior before policies existed.
auto_provision: false

# Each person's grant and standing; defaults to oidc-policy.json beside
# oidc-state.json, written 0600.
policy_file: /config/magpie/oidc-policy.json

# Applications and decisions may go to a generic JSON webhook, a Feishu
# bot, or both. The admin page always lists applications.
notify:
  feishu: https://open.feishu.cn/open-apis/bot/v2/hook/xxxx
  webhook: https://example.com/magpie/events

# An approval system may call POST /hooks/approval, signing the body with
# HMAC-SHA256 in X-Magpie-Signature. Off while empty.
hooks:
  secret: <at least 16 characters>

group_claim: groups          # or realm_access.roles for Keycloak roles
budget:                      # optional, each key's access.Limit
  period: month
  cost: 50

# Per-person overrides, by email (any case) or OIDC subject. "models"
# replaces what the person's groups give and "budget" replaces the budget
# above; leave either out to keep the group's models / the global budget.
# This is how one person's key gets its own model list or monthly cost.
users:
  ops@example.com:
    models: [anthropic, "openai/gpt-5"]
    budget:
      period: month
      cost: 20
  "3f6c…-subject-uuid":
    models: ["anthropic/claude-sonnet-4-5"]  # models only; budget global
```

`groups:` and `users:` are the fallback under approval: a policy's own
models win, then the person's groups. `users:` also feeds first-sign-in
provisioning when `auto_provision` is on. Changing either reaches an
existing key on its next portal visit; the key's id and value stay the same,
and changing only the cap keeps the budget window's `since`.

`state_file` defaults to `oidc-state.json` in magpie's config directory,
`policy_file` to `oidc-policy.json` beside it, and `cookie_secret` to a
32-byte secret made once in `oidc-cookie.key`; all are written 0600.
`provision: false` is the deliberate opt-out that hands out unrestricted
keys and is not the default.

Run it with `make oidc` and `./magpie-oidc -config oidc.yaml`. `-check`
loads the config and performs OIDC discovery, then exits. The portal serves
from the root of its listen address (`/login`, `/callback`, `/admin`), so a
reverse proxy should give it its own hostname or port, not a path prefix.
In Keycloak the client's redirect URI must be `redirect_url`, and the
client needs the `groups` claim (a group membership mapper) unless
`group_claim` names another claim.

## Runtime paths

- `GET /login` makes state, nonce and a PKCE verifier, keeps them in a
  signed, 10-minute `magpie_oidc_flow` cookie, and redirects to the
  provider's authorization endpoint.
- `GET /callback` checks the returned `state` against that cookie, exchanges
  the code with the verifier, verifies the ID token's signature, audience
  and nonce (`Provider.Exchange` in `oidcsidecar/oidcportal/oidc.go`), records
  the person with `PolicyStore.Seen` and sets a 12-hour signed
  `magpie_oidc_session` cookie. No key is made here under approval.
- `GET /` renders by policy status, all in Chinese: `pending` offers
  **申请访问权限** (`POST /request-access`), `requested` waits and may cancel
  (`POST /cancel-request`), `rejected`/`disabled` say so, and `active`
  applies the policy (`ApplyPolicy`: `EnsureScoped` with the policy's models
  and budget, or `RemoveUser` when disabled) and shows the person's page.
  That page is drawn in magpie's own key page (see below): the key masked
  with Copy kept to its owner, its limits as magpie's budget
  bars, today / 7 days / 30 days, the per-day chart, the models it called,
  the recent calls (metadata only, bodies are in Langfuse) and what the key
  may use.
- `POST /rotate` calls `rotate-key`; the key id, scope and on/off state stay,
  and the old value stops working at once. `POST /logout` clears the
  session.
- `GET /admin` lists policies merged with legacy state rows, filterable by
  status and name, with each person's models, budget, spend and last seen.
  `GET /admin/user` is the edit page. `POST /admin/save` validates models and
  budget, approves a `requested` person or updates an `active` one, then
  applies the policy; `reject`, `disable`, `enable`, `remove` and `rotate`
  do what they say. Each action is appended to `oidc-audit.jsonl`.
- `POST /hooks/approval` is off unless `hooks.secret` is set: the raw body
  must carry its HMAC-SHA256 hex in `X-Magpie-Signature`; `action`,
  `sub`, `models` and `budget` approve, and `reject`/`disable`/`enable`
  move the standing.
- `GET /portal/api/me` and
  `GET /portal/api/me/usage?period=month|week|today|all` are the same for a
  script, as JSON; `POST /portal/api/rotate` too. `GET /portal/api/my-key`
  returns the owner's full key to the owner's own browser, which is how the
  Copy button works; the page itself only ever carries the masked value.
- `GET /key` and `GET /v1/magpie/me` are the key page for the ordinary
  user, the same as an admin's: the page is magpie's `keypage.html`
  (`internal/gateway/keypage.html`, embedded as `oidcportal/keypage.html`)
  with its Rotate and its setup's base URL made the portal's, and its data
  is read from the running gateway (`gateway_url`, `http://magpie:3425`) as
  the person's own key. The console proxy leaves `/v1/magpie/me` to the
  portal so the answer is always the signed-in person's key's.
  `POST /key/rotate` is its Rotate (`rotate-key` on their key); its Forget
  and Copy are magpie's.
- `GET /portal/api/key` is the owner's full key for that page's Copy,
  never another person's.
- `GET /me` is magpie's own key page for an admin or super admin, served
  from the portal's sign-in: magpie's page with the portal's Chinese
  (`oidcportal/zh.go`), the holder's own key filled in, and the Copy and
  Rotate buttons working on it. `POST /me/rotate` rotates that key. Its data
  (`/v1/magpie/me`) is asked as the admin's own gateway key, which the
  portal injects and never passes through from the browser. A person whose
  token holds `magpie-operator` or `magpie-super` gets that key on first
  sign-in.
- `GET /healthz` answers `ok` without touching the provider.

## The console behind the portal

With `console_url` set, the portal also serves magpie's own console at
`/console/`, and forwards its absolute `/api`, `/wails` and `/_magpie` paths.
The browser never receives magpie's `MAGPIE_WEB_KEY`: the portal keeps the
console's signed-in cookie for the upstream and strips it from answers.
`console_web_key` is that key, or `MAGPIE_WEB_KEY` from the environment; the
console port itself stays unpublished.

Ordinary admins may read and write six areas — library, providers, gateway,
usage overview, masking and settings. Super admins may additionally open
plugin frames. Both roles are refused every answer that carries a key value
or a request/response body (`copy-key`, `add-key`, `rotate-key`, body and
content endpoints, settings secrets); rotation is done from the portal's
admin page, which does not show the new value. Everything else under `/api`
is deny-by-default, so a newer magpie endpoint cannot widen a role by
existing.

Every form POST is refused unless its `Origin` (or `Referer`) is the
portal's own host; cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` when
`redirect_url` is HTTPS. Pages carry a `default-src 'none'` CSP and
`no-store`.

## State

`caller-keys.json` is the source of truth for keys; `oidc-policy.json` maps
a subject to their standing, models, budget, approval and note, and is the
authority for access. `oidc-state.json` maps a subject to its key id, value,
generation, groups and providers, and is a cache of the key store, not a
second authority. A state row from before policies existed is adopted as an
`active` policy on the person's next visit (`ApprovedBy: "migration"`), with
the key's own models and budget, so an upgrade keeps every key.

The policy store is one JSON object, read once and replaced atomically under
a mutex; a hundred or a thousand people is a small file and each change is
one write. A policy file that cannot be read is an error, never an empty
store, so a damaged file cannot turn a grant into a rejection.

- A key missing from `caller-keys.json` (removed by hand or by a restore)
  is made again on the next visit; the portal never hands out a value no
  gateway knows.
- If `oidc-state.json` is lost, `EnsureUser` adopts the existing key with the
  person's name when exactly one has it and no other state row claims it, so
  a lost file does not duplicate keys. A name another person's record holds
  is suffixed instead of adopted.
- A state file that cannot be read or parsed is an error, never an empty
  store: an empty one would give every user a new key.

One portal serves one magpie. Its writes are serialized within the process
and the file is replaced atomically, but two portals sharing a state file
would not see each other's changes.

Key names are `oidc:<preferred_username>` — what Keycloak calls the person —
falling back to the email's local part and then the subject. A name another
person already holds gets a short subject suffix, and a name longer than
magpie's 120 characters ends in a hash, so two keys never share a name.

## Failure behavior

- A user whose groups match no configured group and who has no default gets
  no key and a 403 page; no key is written.
- A user an admin removed gets 403 until enabled.
- A `users:` entry that sets neither models nor a budget, or names an
  invalid model or budget, is refused when the config loads: a person's
  entry never silently becomes a no-op.
- OIDC discovery failure at startup stops the program: it will not run
  against an issuer it cannot read.
- An ID token with the wrong nonce, audience or signature is refused; the
  login's state is compared in constant time and the flow cookie is
  single-use.

## Verification

```sh
cd oidcsidecar && go test ./... && go vet ./...
GOOS=linux go build ./... && GOOS=windows go build ./...

```

The tests use a fake `OIDCProvider` and temp `XDG_CONFIG_HOME` directories;
they never contact a provider or touch the real `~/.config/magpie`. The
portal tests cover the full login, portal, rotate, admin and no-group paths,
including a provision that enforces the key's models and budget before it
becomes usable.
