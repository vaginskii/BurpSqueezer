# BurpSqueezer Report

## Overview

| metric | value |
|---|---|
| source | catalogue.xml |
| raw transactions | 26 |
| after filtering | 17 (65.4% retained) |
| endpoints | 10 |
| hosts | catalogue.test |
| methods | DELETE, GET: 9, POST: 5, PUT: 2 |
| strong values | 9 |
| data-flow chains | 4 |

## Core Signal

fp:HHHH = stable short fingerprint of a full value; matching uses the full value in memory; full values are not printed in this report by default

### Strong Values

| handle | value | len | entropy | score | seen | coverage | endpoints | propagates | in path | synthetic? | locations |
|---|---|---|---|---|---|---|---|---|---|---|---|
| fp:4c79 | 9a3ca0…a676 [fp:4c79] (36 chars) | 36 | 3.67 | 0.82 | 4 | 17.6% | 2 | yes | no | - | GET /assets/palette.json (resp body.palette[]), PUT /api/accounts/{id}/palette (req body.palette), PUT /api/accounts/{id}/palette (resp body.palette) |
| fp:2fef | 314316…8b61 [fp:2fef] (36 chars) | 36 | 3.65 | 0.82 | 4 | 17.6% | 2 | yes | no | - | GET /assets/tiers.json (resp body.tiers[]), PUT /api/accounts/{id}/tier (req body.tier), PUT /api/accounts/{id}/tier (resp body.tier) |
| fp:baa6 | acct_9…t7Kd [fp:baa6] (17 chars) | 17 | 3.85 | 0.80 | 7 | 23.5% | 4 | yes | yes | - | POST /api/session (resp body.account), GET /api/accounts/{id} (req path), GET /api/accounts/{id} (resp body.account), PUT /api/accounts/{id}/palette (req path), PUT /api/accounts/{id}/palette (resp body.account), PUT /api/accounts/{id}/tier (req path), PUT /api/accounts/{id}/tier (resp body.account) |
| fp:b283 | 4d8c17…0d64 [fp:b283] (40 chars) | 40 | 3.97 | 0.67 | 13 | 76.5% | 8 | yes | no | - | POST /api/session (resp body.token), GET /api/accounts/{id} (req header.authorization), PUT /api/accounts/{id}/palette (req header.authorization), PUT /api/accounts/{id}/tier (req header.authorization), GET /api/rooms/{id}/updates (req header.authorization), POST /api/rooms/{id}/messages (req header.authorization), GET /api/rooms/{id}/members (req header.authorization), DELETE /api/rooms/{id}/members/{id} (req header.authorization) |
| fp:5926 | 990f1d…a4ab [fp:5926] (36 chars) | 36 | 3.87 | 0.59 | 2 | 11.8% | 1 | no | no | - | GET /assets/tiers.json (resp body.tiers[]) |
| fp:6dbf | 7ce31b…195a [fp:6dbf] (36 chars) | 36 | 3.79 | 0.59 | 2 | 11.8% | 1 | no | no | - | GET /assets/tiers.json (resp body.tiers[]) |
| fp:d88e | ffc3b3…3209 [fp:d88e] (36 chars) | 36 | 3.77 | 0.59 | 2 | 11.8% | 1 | no | no | - | GET /assets/tiers.json (resp body.tiers[]) |
| fp:f7b1 | e7020c…ff60 [fp:f7b1] (36 chars) | 36 | 3.73 | 0.59 | 2 | 11.8% | 1 | no | no | - | GET /assets/tiers.json (resp body.tiers[]) |
| fp:1231 | 9601c5…11d5 [fp:1231] (36 chars) | 36 | 3.50 | 0.58 | 2 | 11.8% | 1 | no | no | - | GET /assets/tiers.json (resp body.tiers[]) |

### Multi-Data-Flow Chains

- **fp:baa6** acct_9…t7Kd [fp:baa6] (17 chars) — 7 hops across 4 endpoints, score 1.24
  1. POST /api/session (resp body.account)
  2. GET /api/accounts/{id} (req path)
  3. GET /api/accounts/{id} (resp body.account)
  4. PUT /api/accounts/{id}/palette (req path)
  5. PUT /api/accounts/{id}/palette (resp body.account)
  6. PUT /api/accounts/{id}/tier (req path)
  7. PUT /api/accounts/{id}/tier (resp body.account)
- **fp:4c79** 9a3ca0…a676 [fp:4c79] (36 chars) — 4 hops across 2 endpoints, score 1.22
  1. GET /assets/palette.json (resp body.palette[])
  2. GET /assets/palette.json (resp body.palette[])
  3. PUT /api/accounts/{id}/palette (req body.palette)
  4. PUT /api/accounts/{id}/palette (resp body.palette)
- **fp:2fef** 314316…8b61 [fp:2fef] (36 chars) — 4 hops across 2 endpoints, score 1.22
  1. GET /assets/tiers.json (resp body.tiers[])
  2. GET /assets/tiers.json (resp body.tiers[])
  3. PUT /api/accounts/{id}/tier (req body.tier)
  4. PUT /api/accounts/{id}/tier (resp body.tier)
- **fp:b283** 4d8c17…0d64 [fp:b283] (40 chars) — 13 hops across 8 endpoints, score 1.13
  1. POST /api/session (resp body.token)
  2. GET /api/accounts/{id} (req header.authorization)
  3. PUT /api/accounts/{id}/palette (req header.authorization)
  4. PUT /api/accounts/{id}/tier (req header.authorization)
  5. GET /api/rooms/{id}/updates (req header.authorization)
  6. GET /api/rooms/{id}/updates (req header.authorization)
  7. GET /api/rooms/{id}/updates (req header.authorization)
  8. POST /api/rooms/{id}/messages (req header.authorization)
  9. POST /api/rooms/{id}/messages (req header.authorization)
  10. POST /api/rooms/{id}/messages (req header.authorization)
  11. POST /api/rooms/{id}/messages (req header.authorization)
  12. GET /api/rooms/{id}/members (req header.authorization)
  13. DELETE /api/rooms/{id}/members/{id} (req header.authorization)

### High-Relevance Endpoints

| endpoint | hits | statuses | relevance | why | query | req fields | resp fields | values |
|---|---|---|---|---|---|---|---|---|
| PUT /api/accounts/{id}/palette | 1 | 200 | 0.83 | object_write | - | palette | account, palette | fp:4c79, fp:b283, fp:baa6 |
| PUT /api/accounts/{id}/tier | 1 | 200 | 0.83 | object_write | - | tier | account, tier | fp:2fef, fp:b283, fp:baa6 |
| DELETE /api/rooms/{id}/members/{id} | 1 | 200 | 0.57 | object_write | - | - | removed | fp:b283 |
| POST /api/session | 1 | 200 | 0.57 | auth | - | login | account, token | fp:b283, fp:baa6 |
| GET /assets/tiers.json | 2 | 200 (2) | 0.55 | local_identity | locale | - | tiers[] | fp:1231, fp:2fef, fp:5926, fp:6dbf, fp:d88e, fp:f7b1 |
| GET /api/accounts/{id} | 1 | 200 | 0.46 | object_read | - | - | account, state | fp:b283, fp:baa6 |
| GET /assets/palette.json | 2 | 200 (2) | 0.45 | local_identity | locale | - | palette[] | fp:4c79 |

## Secondary Context

### Other Endpoints

| endpoint | hits | statuses | relevance | query | req fields | resp fields | values |
|---|---|---|---|---|---|---|---|
| POST /api/rooms/{id}/messages | 4 | 201 (4) | 0.16 | - | text | message | fp:b283 |
| GET /api/rooms/{id}/updates | 3 | 200 (3) | 0.04 | cursor | - | cursor | fp:b283 |
| GET /api/rooms/{id}/members | 1 | 200 | 0.03 | - | - | - | fp:b283 |

### Sequences

| sequence | support | linked values |
|---|---|---|
| PUT /api/accounts/{id}/palette → PUT /api/accounts/{id}/tier | 1 | fp:2fef, fp:4c79, fp:baa6 |
| GET /api/accounts/{id} → PUT /api/accounts/{id}/palette | 1 | fp:4c79, fp:baa6 |

### Possible State Indicators

_none_

## Meta

| field | value |
|---|---|
| tool | burpsqueezer {version} |
| mode | standard |
| relaxed for small dump | no |
| transactions dropped | 9 |

### Value Handling

Strong Values are shown truncated with a stable fingerprint. Chains were matched on the full value in memory; full values are never written to this report. propagates=yes when the same value is observed in a chain across more than one hop (any req/resp slot).

Values are judged by where they were seen, never by what a field is named. Path segments, query parameters, cookies and JSON bodies carry application data; plain headers carry protocol scaffolding and take no part in mining unless a value both crossed from one slot into another and is long and random enough to be an issued credential. Coverage is the share of retained transactions carrying the value: the closer it is to 100%, the more the value behaves like a constant, and the harder it is scored down.

### Display Notes

(+N identical) indicates extra identical retained transactions collapsed in display counts. Only state-changing calls with identical input are collapsed; reads are not collapsed.
### Filtering Breakdown

| reason | count |
|---|---|
| statistical: low variation on frequent endpoint | 9 |

### Truncations

_none_

### Warnings

_none_

