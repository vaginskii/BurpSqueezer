# BurpSqueezer Report

## Overview

| metric | value |
|---|---|
| source | tiny.xml |
| raw transactions | 2 |
| after filtering | 2 (100.0% retained) |
| endpoints | 2 |
| hosts | shop.test |
| methods | GET, POST |
| strong values | 2 |
| data-flow chains | 2 |

## Core Signal

fp:HHHH = stable short fingerprint of a full value; matching uses the full value in memory; full values are not printed in this report by default

### Strong Values

| handle | value | len | entropy | score | seen | coverage | endpoints | propagates | in path | synthetic? | locations |
|---|---|---|---|---|---|---|---|---|---|---|---|
| fp:a3c0 | c9f4a1…0c31 [fp:a3c0] (32 chars) | 32 | 3.89 | 0.52 | 2 | 100.0% | 2 | yes | no | - | POST /api/auth/session (resp body.session_token), GET /api/users/{id} (req header.authorization) |
| fp:0045 | <14 chars> [fp:0045] | 14 | 3.66 | 0.38 | 2 | 100.0% | 2 | no | no | - | POST /api/auth/session (resp body.user_ref), GET /api/users/{id} (resp body.user_ref) |

### Multi-Data-Flow Chains

- **fp:a3c0** c9f4a1…0c31 [fp:a3c0] (32 chars) — 2 hops across 2 endpoints, score 0.92
  1. POST /api/auth/session (resp body.session_token)
  2. GET /api/users/{id} (req header.authorization)
- **fp:0045** <14 chars> [fp:0045] — 2 hops across 2 endpoints, score 0.43
  1. POST /api/auth/session (resp body.user_ref)
  2. GET /api/users/{id} (resp body.user_ref)

### High-Relevance Endpoints

| endpoint | hits | statuses | relevance | why | query | req fields | resp fields | values |
|---|---|---|---|---|---|---|---|---|
| POST /api/auth/session | 1 | 200 | 0.18 | auth | - | login | session_token, state, user_ref | fp:0045, fp:a3c0 |
| GET /api/users/{id} | 1 | 200 | 0.07 | object_read | - | - | state, tier, user_ref | fp:0045, fp:a3c0 |

## Secondary Context

### Other Endpoints

_none_

### Sequences

_none_

### Possible State Indicators

_none_

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

- Small dump (2 transactions): thresholds were relaxed, so signal is less reliable than usual.

