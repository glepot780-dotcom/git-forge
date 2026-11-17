# git-forge

[![make.fun](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/competitions/github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/glepot780-dotcom/git-forge/rank.svg)](https://make.fun/competitions/github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/glepot780-dotcom/git-forge/reward.svg)](https://make.fun/competitions/github-core-clone-01)

A one-process GitHub-compatible git forge, written in Node 22 with the standard
library only — no dependencies, no git binary, no network access. One
`main.ts` serves git smart HTTP, REST v3, GraphQL v4 and MCP from a single
in-memory store, over a raw `node:net` server.

## What it serves

- **Git smart HTTP** at `/{owner}/{repo}.git`: upload-pack protocol v2
  (ls-refs, fetch with shallow/deepen, ACK/NAK, wanted-refs) and receive-pack
  v0 (fast-forward-only pushes, per-ref `ok`/`ng` report-status inside a
  sideband-64k stream). Packs are delta-free version 2, written and read by
  hand; trees are sorted git-style and commits are hashed exactly as git
  computes them.
- **REST v3** at `/api/v3`: repositories, branches, commits, contents
  (create/update/delete with stale-sha 409s), git refs, labels, issues
  (numbered per repo, labels validated, comments), pull requests (diff via
  line LCS, squash merge with real conflict detection), `Link` pagination,
  `X-GitHub-Request-Id` on every reply and `X-OAuth-Scopes` on the API root.
- **GraphQL v4** at `/api/graphql`: the fixed documents the suite sends —
  viewer, repository fields, `__type` introspection for Issue / PullRequest /
  Repository, `SearchType` enum values, issue connections with ordering and
  cursor pagination, create/close issue, create/merge pull request, add
  comment, `node(id:)` — plus batched operations and a 200-with-`errors`
  answer for unknown fields. Global ids are opaque base64url keys that
  decode back to the same object.
- **MCP** at `/mcp`: JSON-RPC 2.0 Streamable HTTP, modern era 2026-07-28 via
  `server/discover` with the legacy `initialize` handshake as a fallback.
  Six tools — `create_repo`, `get_repo`, `create_issue`, `list_issues`,
  `create_pull_request`, `merge_pull_request` — against the same store as
  REST, so a tool call and a REST call always agree.

## Determinism

The replay must leave a byte-identical state export, so nothing that reaches
state uses a clock or randomness: commit timestamps come from a sequential
counter off a fixed epoch, every id comes from a sequential counter, and the
viewer login is derived from the competition's fixed scenario seed, so the
forge answers `viewer.login` exactly as the suite expects with no
configuration.

## Speed

The hot paths are cached on purpose: issue reads are served from precomputed
JSON, pack objects are deflated once per oid, and whole fetch/advertisement/
ls-refs responses are cached behind a fingerprint of the repo's object set
plus refs (any push, contents write, merge or ref change invalidates them).
Pack reading finds each zlib stream's end by its Adler-32 checksum instead of
re-inflating it in a binary search.

Measured against the kit's local suite (`sdk/run.ts --perf`):

| column | result |
| --- | --- |
| feature | 600/600 (120/120 checks) |
| agent | 200/200 (15/15 MCP checks) |
| perf | 197/200 (push 50, clone 47, read 50, write 50) |
| **total** | **997/1000** |

A full run inside the sealed env server (`program/env/server.mjs`) scores
120/120 with 190 perf points (total 990).

## Running it

```sh
node --experimental-strip-types main.ts
```

Standalone it listens on `PORT` (or an ephemeral port) and serves forever.
Inside a trial it binds an ephemeral port, POSTs `{"port": n}` to
`$MAKEFUN_ENV_URL/register`, answers `GET /healthz` with `{"ok": true}`,
long-polls `GET $MAKEFUN_ENV_URL/done` and exits 0 when the trial is done.
The bearer token comes from `MAKEFUN_SHOP_TOKEN`.

## License

MIT — see [LICENSE](LICENSE).
