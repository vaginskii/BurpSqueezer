# BurpSqueezer

**Turn large Burp Suite XML dumps into compact Markdown reports for LLM analysis.**

BurpSqueezer is a security research tool that transforms large Burp Suite HTTP traffic dumps into highly compact, structured Markdown representations designed to be consumed by LLMs.

Instead of giving an LLM a large amount of raw HTTP traffic and expecting it to parse, filter, and connect everything itself, BurpSqueezer performs the initial structural analysis and removes a significant amount of redundant and low-value data.

```text
Large Burp Suite XML dump
          │
          ▼
     BurpSqueezer
          │
          ▼
Compact structured Markdown
          │
          ▼
    Human / LLM analysis
```

## Why BurpSqueezer?

Large Burp Suite dumps can contain hundreds or thousands of HTTP transactions, including repeated requests, infrastructure noise, dynamic values, headers, responses, and other data that is expensive or impractical to provide directly to an LLM.

BurpSqueezer is designed to reduce this dataset while preserving useful information about the application's underlying structure.

The resulting report can be substantially smaller than the original dump, making it more practical for LLM-based analysis, especially in environments with file-size, context-window, or token-budget limitations.

BurpSqueezer is **not an autonomous pentester**. It prepares and compresses application traffic into a representation that can be further analyzed by humans or LLMs. Final security conclusions and verification still require manual testing.

## Philosophy

BurpSqueezer is designed as a universal tool with no hardcoded endpoints or application-specific patterns. Instead of assuming how an API is structured, it uses statistical and heuristic analysis to identify potentially meaningful relationships within the observed traffic.

A key goal is **information-dense compression**: reducing large HTTP request dumps into much smaller representations while retaining useful structural, relational, and data-flow information.

This makes the resulting reports practical as LLM context even when the original Burp dataset would be too large, expensive, or otherwise impractical to provide directly to an AI model.

BurpSqueezer is designed primarily for **APIs and applications with meaningful business logic**. Simple websites with little or no backend logic may produce significantly less useful results because there may be insufficient structure and relationships for the tool to analyze.

## Features

* **Universal Analysis** — No hardcoded endpoints, application patterns, or assumptions about API structure
* **High Compression** — Reduces large HTTP request dumps into significantly smaller reports while preserving relevant analytical information
* **Noise Filtering** — Uses statistical and heuristic techniques to reduce redundant and low-value traffic
* **Data Flow Tracking** — Identifies value propagation and relationships between requests
* **Structural Analysis** — Extracts relationships, sequences, states, and other signals from observed traffic
* **LLM-Optimized Output** — Produces compact Markdown designed to be used as context for LLM-based analysis
* **Multiple Modes** — Adjustable selectivity depending on whether completeness or maximum compression is preferred

## Real-World Compression

A test on a real Burp Suite XML dump demonstrated substantial size reduction:

| Mode          | Compression |
| ------------- | ----------: |
| `peaceful`    |    **347×** |
| `standard`    |    **745×** |
| `apocalyptic` |   **1738×** |

In the `standard` test, an approximately **26.7 MB** Burp Suite XML dump containing **323 transactions** was reduced to approximately **35 KB** of structured Markdown.

The original traffic is not included in this repository because real Burp captures may contain sensitive application data, credentials, tokens, or other private information.

Compression results naturally vary depending on the structure and contents of the input dataset.

## Installation

```bash
cargo install --path .
```

## Usage

```bash
burpsqueezer solve input.xml --output report.md --mode standard
```

### Modes

* `peaceful` — lower thresholds and a fuller report; preserves more potentially useful information
* `standard` — balanced default mode between information retention and compression
* `apocalyptic` — maximum selectivity; focuses on the strongest structural signals

### Options

* `--output` — destination for the Markdown report (required)
* `--mode` — analysis mode (default: `standard`)
* `--quiet` — silence all progress output
* `--verbose` — emit per-stage detail

## Examples

```bash
# Basic usage
burpsqueezer solve burp_dump.xml --output analysis.md

# Maximum // Lowest selectivity
burpsqueezer solve large_dump.xml --output focused.md --mode apocalyptic // --mode peaceful

# Verbose output for debugging
burpsqueezer solve test.xml --output report.md --verbose
```

## Output

BurpSqueezer transforms raw Burp Suite XML traffic into a structured and highly compact Markdown representation intended for both human review and LLM-based analysis.

The generated report can contain information about:

* API endpoints and their relationships
* Request and response patterns
* Parameter and value propagation
* Data flows between requests
* Sequences and structural relationships
* State-related indicators
* Statistical relationships between endpoints
* Relevant signals identified after noise reduction

The exact output depends on the input dataset and selected analysis mode.

BurpSqueezer is **not intended to simply summarize HTTP traffic**. Its goal is to produce a compact, security-oriented representation of the underlying API structure and relationships while removing a significant amount of redundant and low-value data.

The original Burp dump can still be useful for manual verification or retrieving information that was intentionally omitted during compression.

## Relationship with Burp Suite

BurpSqueezer is an independent security research tool and is **not affiliated with, endorsed by, or developed by PortSwigger**.

It does not contain or distribute Burp Suite software.

BurpSqueezer operates on HTTP traffic exported by the user from Burp Suite. The input is user-provided Burp Suite XML data; BurpSqueezer does not interact with or send requests to the target application.

## Limitations

This is an experimental security research tool. Results may vary across different Burp collections.

BurpSqueezer is primarily designed for large datasets and applications with meaningful API structure or business logic. Small, highly specialized, or structurally sparse datasets may provide less information for the statistical analysis to work with.

Statistical and heuristic analysis cannot guarantee that every relevant relationship, data flow, or security signal will be identified.

Aggressive compression modes may intentionally discard information in exchange for a smaller output.

BurpSqueezer is intended to assist human and LLM-based analysis, **not replace manual security testing or verification**.

## Responsible Use

BurpSqueezer is intended for authorized security testing, penetration testing, bug bounty programs, and security research.

Only analyze HTTP traffic that you are authorized to access. Do not use BurpSqueezer with data obtained from systems or applications without appropriate permission.

The author is not responsible for misuse of the software.

## License

See the `LICENSE` file for the terms under which BurpSqueezer is distributed.
