# BurpSqueezer Report

## Overview

| metric | value |
|---|---|
| source | header_noise.xml |
| raw transactions | 30 |
| after filtering | 30 (100.0% retained) |
| endpoints | 25 |
| hosts | app.example.com |
| methods | DELETE, GET: 25, POST: 4 |
| strong values | 6 |
| data-flow chains | 6 |

## Core Signal

fp:HHHH = stable short fingerprint of a full value; matching uses the full value in memory; full values are not printed in this report by default

### Strong Values

| handle | value | len | entropy | score | seen | coverage | endpoints | propagates | in path | synthetic? | locations |
|---|---|---|---|---|---|---|---|---|---|---|---|
| fp:2ba4 | <14 chars> [fp:2ba4] | 14 | 3.81 | 0.80 | 6 | 16.7% | 5 | yes | yes | - | POST /api/auth/session (resp body.user.id), GET /api/me (resp body.id), GET /api/workspaces/wks_8Hq2Lm4Rt9/members (resp body.items[].id), POST /api/channels/chn_2Vb6Xy8Qs4/messages (resp body.author), GET /api/users/{id} (req path), GET /api/users/{id} (resp body.id) |
| fp:f0cd | <14 chars> [fp:f0cd] | 14 | 3.81 | 0.80 | 7 | 20.0% | 5 | yes | yes | - | POST /api/auth/session (resp body.workspace.id), GET /api/workspaces/wks_8Hq2Lm4Rt9 (req path), GET /api/workspaces/wks_8Hq2Lm4Rt9 (resp body.id), GET /api/workspaces/wks_8Hq2Lm4Rt9/members (req path), GET /api/workspaces/wks_8Hq2Lm4Rt9/channels (req path), POST /api/workspaces/wks_8Hq2Lm4Rt9/invites (req path) |
| fp:bdc4 | <14 chars> [fp:bdc4] | 14 | 3.81 | 0.79 | 3 | 10.0% | 3 | yes | yes | - | GET /api/workspaces/wks_8Hq2Lm4Rt9/channels (resp body.items[].id), GET /api/channels/chn_2Vb6Xy8Qs4/messages (req path), POST /api/channels/chn_2Vb6Xy8Qs4/messages (req path) |
| fp:6b94 | <14 chars> [fp:6b94] | 14 | 3.81 | 0.79 | 5 | 10.0% | 3 | yes | yes | - | POST /api/workspaces/wks_8Hq2Lm4Rt9/invites (resp body.invite_id), GET /api/invites/inv_9Tk1Nc7Rw3 (req path), GET /api/invites/inv_9Tk1Nc7Rw3 (resp body.id), DELETE /api/invites/inv_9Tk1Nc7Rw3 (req path), DELETE /api/invites/inv_9Tk1Nc7Rw3 (resp body.id) |
| fp:a5a2 | c1f4a9…0c31 [fp:a5a2] (32 chars) | 32 | 3.89 | 0.78 | 14 | 46.7% | 11 | yes | no | - | POST /api/auth/session (resp body.access_token), GET /api/me (req header.authorization), GET /api/workspaces/wks_8Hq2Lm4Rt9 (req header.authorization), GET /api/workspaces/wks_8Hq2Lm4Rt9/members (req header.authorization), GET /api/workspaces/wks_8Hq2Lm4Rt9/channels (req header.authorization), GET /api/channels/chn_2Vb6Xy8Qs4/messages (req header.authorization), POST /api/channels/chn_2Vb6Xy8Qs4/messages (req header.authorization), GET /api/users/{id} (req header.authorization), POST /api/workspaces/wks_8Hq2Lm4Rt9/invites (req header.authorization), GET /api/invites/inv_9Tk1Nc7Rw3 (req header.authorization), DELETE /api/invites/inv_9Tk1Nc7Rw3 (req header.authorization) |
| fp:4681 | <14 chars> [fp:4681] | 14 | 3.81 | 0.75 | 2 | 6.7% | 2 | yes | no | - | POST /api/auth/challenge (resp body.challenge_id), POST /api/auth/session (req body.challenge_id) |

### Multi-Data-Flow Chains

- **fp:f0cd** <14 chars> [fp:f0cd] — 7 hops across 5 endpoints, score 1.25
  1. POST /api/auth/session (resp body.workspace.id)
  2. GET /api/workspaces/wks_8Hq2Lm4Rt9 (req path)
  3. GET /api/workspaces/wks_8Hq2Lm4Rt9 (resp body.id)
  4. GET /api/workspaces/wks_8Hq2Lm4Rt9/members (req path)
  5. GET /api/workspaces/wks_8Hq2Lm4Rt9/members (req path)
  6. GET /api/workspaces/wks_8Hq2Lm4Rt9/channels (req path)
  7. POST /api/workspaces/wks_8Hq2Lm4Rt9/invites (req path)
- **fp:2ba4** <14 chars> [fp:2ba4] — 6 hops across 5 endpoints, score 1.25
  1. POST /api/auth/session (resp body.user.id)
  2. GET /api/me (resp body.id)
  3. GET /api/workspaces/wks_8Hq2Lm4Rt9/members (resp body.items[].id)
  4. POST /api/channels/chn_2Vb6Xy8Qs4/messages (resp body.author)
  5. GET /api/users/{id} (req path)
  6. GET /api/users/{id} (resp body.id)
- **fp:a5a2** c1f4a9…0c31 [fp:a5a2] (32 chars) — 14 hops across 11 endpoints, score 1.25
  1. POST /api/auth/session (resp body.access_token)
  2. GET /api/me (req header.authorization)
  3. GET /api/workspaces/wks_8Hq2Lm4Rt9 (req header.authorization)
  4. GET /api/workspaces/wks_8Hq2Lm4Rt9/members (req header.authorization)
  5. GET /api/workspaces/wks_8Hq2Lm4Rt9/members (req header.authorization)
  6. GET /api/workspaces/wks_8Hq2Lm4Rt9/channels (req header.authorization)
  7. GET /api/channels/chn_2Vb6Xy8Qs4/messages (req header.authorization)
  8. POST /api/channels/chn_2Vb6Xy8Qs4/messages (req header.authorization)
  9. GET /api/users/{id} (req header.authorization)
  10. GET /api/users/{id} (req header.authorization)
  11. GET /api/users/{id} (req header.authorization)
  12. POST /api/workspaces/wks_8Hq2Lm4Rt9/invites (req header.authorization)
  13. GET /api/invites/inv_9Tk1Nc7Rw3 (req header.authorization)
  14. DELETE /api/invites/inv_9Tk1Nc7Rw3 (req header.authorization)
- **fp:6b94** <14 chars> [fp:6b94] — 5 hops across 3 endpoints, score 1.21
  1. POST /api/workspaces/wks_8Hq2Lm4Rt9/invites (resp body.invite_id)
  2. GET /api/invites/inv_9Tk1Nc7Rw3 (req path)
  3. GET /api/invites/inv_9Tk1Nc7Rw3 (resp body.id)
  4. DELETE /api/invites/inv_9Tk1Nc7Rw3 (req path)
  5. DELETE /api/invites/inv_9Tk1Nc7Rw3 (resp body.id)
- **fp:bdc4** <14 chars> [fp:bdc4] — 3 hops across 3 endpoints, score 1.21
  1. GET /api/workspaces/wks_8Hq2Lm4Rt9/channels (resp body.items[].id)
  2. GET /api/channels/chn_2Vb6Xy8Qs4/messages (req path)
  3. POST /api/channels/chn_2Vb6Xy8Qs4/messages (req path)
- **fp:4681** <14 chars> [fp:4681] — 2 hops across 2 endpoints, score 1.15
  1. POST /api/auth/challenge (resp body.challenge_id)
  2. POST /api/auth/session (req body.challenge_id)

### High-Relevance Endpoints

| endpoint | hits | statuses | relevance | why | query | req fields | resp fields | values |
|---|---|---|---|---|---|---|---|---|
| POST /api/channels/chn_2Vb6Xy8Qs4/messages | 1 | 201 | 0.86 | object_write | - | text | author, id | fp:2ba4, fp:a5a2, fp:bdc4 |
| POST /api/workspaces/wks_8Hq2Lm4Rt9/invites | 1 | 201 | 0.86 | object_write | - | email | invite_id | fp:6b94, fp:a5a2, fp:f0cd |
| DELETE /api/invites/inv_9Tk1Nc7Rw3 | 1 | 200 | 0.82 | object_write | - | - | id, state | fp:6b94, fp:a5a2 |
| POST /api/auth/session | 1 | 201 | 0.72 | auth | - | challenge_id, proof | access_token, user.id, workspace.id | fp:2ba4, fp:4681, fp:a5a2, fp:f0cd |
| POST /api/auth/challenge | 1 | 200 | 0.57 | auth | - | login | challenge_id, ttl | fp:4681 |
| GET /api/workspaces/wks_8Hq2Lm4Rt9/members | 2 | 200 (2) | 0.53 | object_read | page | - | items[].id | fp:2ba4, fp:a5a2, fp:f0cd |
| GET /api/workspaces/wks_8Hq2Lm4Rt9/channels | 1 | 200 | 0.53 | object_read | - | - | items[].id | fp:a5a2, fp:bdc4, fp:f0cd |
| GET /api/invites/inv_9Tk1Nc7Rw3 | 1 | 200 | 0.46 | object_read | - | - | id, state | fp:6b94, fp:a5a2 |
| GET /api/me | 1 | 200 | 0.46 | local_identity | - | - | id, name | fp:2ba4, fp:a5a2 |
| GET /api/workspaces/wks_8Hq2Lm4Rt9 | 1 | 200 | 0.46 | object_read | - | - | id, plan | fp:a5a2, fp:f0cd |
| GET /api/users/{id} | 3 | 200 (3) | 0.45 | object_read | - | - | id | fp:2ba4, fp:a5a2 |
| GET /api/channels/chn_2Vb6Xy8Qs4/messages | 1 | 200 | 0.45 | object_read | limit | - | items[].id | fp:a5a2, fp:bdc4 |

## Secondary Context

### Other Endpoints

| endpoint | hits | statuses | relevance | query | req fields | resp fields | values |
|---|---|---|---|---|---|---|---|
| GET /api/locales/ru | 2 | 200 (2) | 0.02 | bundle | - | n, ok | - |
| GET /api/config | 1 | 200 | 0.02 | - | - | env, region | - |
| GET /api/features | 1 | 200 | 0.02 | scope | - | calls, chat | - |
| GET /api/limits | 1 | 200 | 0.02 | - | - | burst, rps | - |
| GET /api/locales/en | 1 | 200 | 0.02 | bundle | - | n, ok | - |
| GET /api/oauth/providers | 1 | 200 | 0.02 | - | - | google, sso | - |
| GET /api/public/manifest | 1 | 200 | 0.02 | - | - | name, version | - |
| GET /api/status/build | 1 | 200 | 0.02 | - | - | clean, sha | - |
| GET /api/status/regions | 1 | 200 | 0.02 | - | - | eu, us | - |
| GET /api/public/themes | 2 | 200 (2) | 0.01 | name | - | bg | - |

### Sequences

_none_

### Possible State Indicators

_none_

## Meta

| field | value |
|---|---|
| tool | burpsqueezer {version} |
| mode | apocalyptic |
| relaxed for small dump | no |
| transactions dropped | 0 |

### Value Handling

Strong Values are shown truncated with a stable fingerprint. Chains were matched on the full value in memory; full values are never written to this report. propagates=yes when the same value is observed in a chain across more than one hop (any req/resp slot).

Values are judged by where they were seen, never by what a field is named. Path segments, query parameters, cookies and JSON bodies carry application data; plain headers carry protocol scaffolding and take no part in mining unless a value both crossed from one slot into another and is long and random enough to be an issued credential. Coverage is the share of retained transactions carrying the value: the closer it is to 100%, the more the value behaves like a constant, and the harder it is scored down.

### Display Notes

(+N identical) indicates extra identical retained transactions collapsed in display counts. Only state-changing calls with identical input are collapsed; reads are not collapsed.
### Filtering Breakdown

_none_

### Truncations

- other endpoints: showing 10 of 13 (limited by --mode apocalyptic)

### Warnings

_none_

