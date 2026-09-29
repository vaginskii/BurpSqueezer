# BurpSqueezer Report

## Overview

| metric | value |
|---|---|
| source | dataflow.xml |
| raw transactions | 9 |
| after filtering | 9 (100.0% retained) |
| endpoints | 4 |
| hosts | shop.test |
| methods | GET: 6, POST: 3 |
| strong values | 8 |
| data-flow chains | 8 |

## Core Signal

fp:HHHH = stable short fingerprint of a full value; matching uses the full value in memory; full values are not printed in this report by default

### Strong Values

| handle | value | len | entropy | score | seen | coverage | endpoints | propagates | in path | synthetic? | locations |
|---|---|---|---|---|---|---|---|---|---|---|---|
| fp:04c6 | 3f2504…3301 [fp:04c6] (36 chars) | 36 | 3.62 | 1.13 | 3 | 22.2% | 2 | yes | yes | - | POST /api/orders (resp body.order_ref), GET /api/orders/{id} (req path), GET /api/orders/{id} (resp body.order_ref) |
| fp:f796 | 9b1deb…cb6d [fp:f796] (36 chars) | 36 | 3.27 | 1.12 | 3 | 22.2% | 2 | yes | yes | - | POST /api/orders (resp body.order_ref), GET /api/orders/{id} (req path), GET /api/orders/{id} (resp body.order_ref) |
| fp:bfdd | <14 chars> [fp:bfdd] | 14 | 3.81 | 1.01 | 3 | 33.3% | 3 | yes | no | - | GET /api/users/{id} (resp body.user_ref), POST /api/orders (req body.user_ref), GET /api/orders/{id} (resp body.user_ref) |
| fp:0045 | <14 chars> [fp:0045] | 14 | 3.66 | 0.71 | 5 | 55.6% | 4 | yes | no | - | POST /api/auth/session (resp body.user_ref), GET /api/users/{id} (resp body.user_ref), POST /api/orders (req body.user_ref), GET /api/orders/{id} (resp body.user_ref) |
| fp:a3c0 | c9f4a1…0c31 [fp:a3c0] (32 chars) | 32 | 3.89 | 0.70 | 9 | 100.0% | 4 | yes | no | - | POST /api/auth/session (resp body.session_token), GET /api/users/{id} (req header.authorization), POST /api/orders (req header.authorization), GET /api/orders/{id} (req header.authorization) |
| fp:8672 | <6 chars> [fp:8672] | 6 | 2.25 | 0.41 | 4 | 44.4% | 2 | no | yes | - | POST /api/orders (req path), GET /api/orders/{id} (req path) |
| fp:138b | <6 chars> [fp:138b] | 6 | 2.58 | 0.39 | 4 | 44.4% | 2 | no | no | - | POST /api/auth/session (resp body.state), GET /api/users/{id} (resp body.state) |
| fp:1481 | <7 chars> [fp:1481] | 7 | 2.52 | 0.38 | 2 | 22.2% | 2 | no | no | - | POST /api/orders (resp body.state), GET /api/orders/{id} (resp body.state) |

### Multi-Data-Flow Chains

- **fp:04c6** 3f2504…3301 [fp:04c6] (36 chars) — 3 hops across 2 endpoints, score 1.53
  1. POST /api/orders (resp body.order_ref)
  2. GET /api/orders/{id} (req path)
  3. GET /api/orders/{id} (resp body.order_ref)
- **fp:f796** 9b1deb…cb6d [fp:f796] (36 chars) — 3 hops across 2 endpoints, score 1.52
  1. POST /api/orders (resp body.order_ref)
  2. GET /api/orders/{id} (req path)
  3. GET /api/orders/{id} (resp body.order_ref)
- **fp:bfdd** <14 chars> [fp:bfdd] — 3 hops across 3 endpoints, score 1.43
  1. GET /api/users/{id} (resp body.user_ref)
  2. POST /api/orders (req body.user_ref)
  3. GET /api/orders/{id} (resp body.user_ref)
- **fp:0045** <14 chars> [fp:0045] — 5 hops across 4 endpoints, score 1.15
  1. POST /api/auth/session (resp body.user_ref)
  2. GET /api/users/{id} (resp body.user_ref)
  3. POST /api/orders (req body.user_ref)
  4. GET /api/orders/{id} (resp body.user_ref)
  5. GET /api/users/{id} (resp body.user_ref)
- **fp:a3c0** c9f4a1…0c31 [fp:a3c0] (32 chars) — 9 hops across 4 endpoints, score 1.14
  1. POST /api/auth/session (resp body.session_token)
  2. GET /api/users/{id} (req header.authorization)
  3. POST /api/orders (req header.authorization)
  4. GET /api/orders/{id} (req header.authorization)
  5. GET /api/users/{id} (req header.authorization)
  6. POST /api/orders (req header.authorization)
  7. GET /api/orders/{id} (req header.authorization)
  8. GET /api/users/{id} (req header.authorization)
  9. GET /api/users/{id} (req header.authorization)
- **fp:8672** <6 chars> [fp:8672] — 4 hops across 2 endpoints, score 0.46
  1. POST /api/orders (req path)
  2. GET /api/orders/{id} (req path)
  3. POST /api/orders (req path)
  4. GET /api/orders/{id} (req path)
- **fp:138b** <6 chars> [fp:138b] — 4 hops across 2 endpoints, score 0.44
  1. POST /api/auth/session (resp body.state)
  2. GET /api/users/{id} (resp body.state)
  3. GET /api/users/{id} (resp body.state)
  4. GET /api/users/{id} (resp body.state)
- **fp:1481** <7 chars> [fp:1481] — 2 hops across 2 endpoints, score 0.43
  1. POST /api/orders (resp body.state)
  2. GET /api/orders/{id} (resp body.state)

### High-Relevance Endpoints

| endpoint | hits | statuses | relevance | why | query | req fields | resp fields | values |
|---|---|---|---|---|---|---|---|---|
| POST /api/orders | 2 | 201 (2) | 0.74 | local_identity | - | sku, user_ref | order_ref, state | fp:0045, fp:04c6, fp:1481, fp:8672, fp:a3c0, fp:bfdd, fp:f796 |
| GET /api/orders/{id} | 2 | 200 (2) | 0.63 | object_read | - | - | order_ref, state, user_ref | fp:0045, fp:04c6, fp:1481, fp:8672, fp:a3c0, fp:bfdd, fp:f796 |
| POST /api/auth/session | 1 | 200 | 0.58 | auth | - | login | session_token, state, user_ref | fp:0045, fp:138b, fp:a3c0 |
| GET /api/users/{id} | 4 | 200 (4) | 0.56 | object_read | - | - | state, tier, user_ref | fp:0045, fp:138b, fp:a3c0, fp:bfdd |

## Secondary Context

### Other Endpoints

_none_

### Sequences

| sequence | support | linked values |
|---|---|---|
| GET /api/orders/{id} → GET /api/users/{id} | 2 | fp:04c6, fp:138b, fp:1481, fp:8672, fp:bfdd, fp:f796 |
| GET /api/users/{id} → POST /api/orders | 2 | fp:04c6, fp:138b, fp:1481, fp:8672, fp:bfdd, fp:f796 |
| POST /api/orders → GET /api/orders/{id} | 2 | fp:04c6, fp:1481, fp:8672, fp:bfdd, fp:f796 |
| POST /api/auth/session → GET /api/users/{id} | 1 | fp:138b, fp:bfdd |
| GET /api/users/{id} → GET /api/users/{id} | 1 | fp:138b, fp:bfdd |

### Possible State Indicators

| endpoint | field | observed values | coverage |
|---|---|---|---|
| GET /api/users/{id} | state | active (3), blocked | 100.0% |

## Meta

| field | value |
|---|---|
| tool | burpsqueezer {version} |
| mode | standard |
| relaxed for small dump | yes |
| transactions dropped | 0 |

### Value Handling

Strong Values are shown truncated with a stable fingerprint. Chains were matched on the full value in memory; full values are never written to this report. propagates=yes when the same value is observed in a chain across more than one hop (any req/resp slot).

Values are judged by where they were seen, never by what a field is named. Path segments, query parameters, cookies and JSON bodies carry application data; plain headers carry protocol scaffolding and take no part in mining unless a value both crossed from one slot into another and is long and random enough to be an issued credential. Coverage is the share of retained transactions carrying the value: the closer it is to 100%, the more the value behaves like a constant, and the harder it is scored down.

### Display Notes

(+N identical) indicates extra identical retained transactions collapsed in display counts. Only state-changing calls with identical input are collapsed; reads are not collapsed.
### Filtering Breakdown

_none_

### Truncations

_none_

### Warnings

- Small dump (9 transactions): thresholds were relaxed, so signal is less reliable than usual.

