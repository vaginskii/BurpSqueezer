# BurpSqueezer

**Turn Burp Suite XML dumps into compact, LLM-ready Markdown reports.**


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
     LLM analysis
```


## Why BurpSqueezer?


Large Burp Suite dumps can contain hundreds or thousands of HTTP transactions, including repeated requests, infrastructure noise, dynamic values, headers, responses, and other data that is expensive or impractical to provide directly to an LLM.


BurpSqueezer is designed to reduce this dataset while preserving useful information about the application's underlying structure.


The resulting report can be substantially smaller than the original dump, making it more practical for LLM-based analysis, especially in environments with file-size, context-window, or token-budget limitations.


BurpSqueezer is **not an autonomous pentester**. It prepares and compresses application traffic into a representation that can be further analyzed by humans or LLMs. Final security conclusions and verification still require manual testing.


## Real-World Compression


A test on a real Burp Suite XML dump demonstrated substantial size reduction:


| Mode          | Compression |  Report size |
| ------------- | ----------: | -----------: |
| `peaceful`    |    **284×** |      94.1 KB |
| `standard`    |    **736×** |      36.3 KB |
| `strict`      |   **1160×** |      23.0 KB |
| `apocalyptic` |   **1543×** |      17.3 KB |


Measured on a **26.7 MB** Burp Suite XML dump containing **323 transactions** from a chat and messaging API, which compresses to roughly 36 KB in `standard` mode.


The original traffic is not included in this repository because real Burp captures may contain sensitive application data, credentials, tokens, or other private information.


Compression results naturally vary depending on the structure and contents of the input dataset. Modes further along the table discard real findings in exchange for a smaller file, so the right mode depends on whether you are looking for something specific or handing the report to a model with a tight context budget.


## Philosophy


BurpSqueezer is designed as a universal tool with no hardcoded endpoints or application-specific patterns. Instead of assuming how an API is structured, it uses statistical and heuristic analysis to identify potentially meaningful relationships within the observed traffic.


A key goal is **information-dense compression**: reducing large HTTP request dumps into much smaller representations while retaining useful structural, relational, and data-flow information.


BurpSqueezer is designed primarily for **APIs and applications with meaningful business logic**. Simple websites with little or no backend logic may produce significantly less useful results because there may be insufficient structure and relationships for the tool to analyze.


## Features


* **Universal Analysis** — No hardcoded endpoints, application patterns, or assumptions about API structure
* **High Compression** — Reduces large HTTP request dumps into significantly smaller reports while preserving relevant analytical information
* **Noise Filtering** — Uses statistical and heuristic techniques to reduce redundant and low-value traffic
* **Data Flow Tracking** — Identifies value propagation and relationships between requests
* **Structural Analysis** — Extracts relationships, sequences, states, and other signals from observed traffic
* **LLM-Optimized Output** — Produces compact Markdown designed to be used as context for LLM-based analysis
* **Value Masking** — Redacts credential-shaped and identity-shaped values by default, so a report can be handed to an external model without first scrubbing it
* **Multiple Modes** — Adjustable selectivity depending on whether completeness or maximum compression is preferred


## Installation


BurpSqueezer is written in Rust. Make sure you have the **Rust toolchain** installed before continuing.


If Rust is not installed, install it from the official Rust website.


Then clone the repository and install BurpSqueezer:


```bash
git clone https://github.com/vaginskii/BurpSqueezer.git
cd BurpSqueezer
cargo install --path .
```


After installation, verify that BurpSqueezer is available:


```bash
burpsqueezer --help
```


If the command displays the available options, the installation was successful.




## Usage


```bash
# Basic usage
burpsqueezer solve burp_dump.xml --output analysis.md


# Maximum selectivity
burpsqueezer solve large_dump.xml --output focused.md --mode apocalyptic


# Lowest selectivity
burpsqueezer solve large_dump.xml --output full.md --mode peaceful


# Print every value in full — for local analysis only
burpsqueezer solve burp_dump.xml --output raw.md --secrets false


# Verbose output for debugging
burpsqueezer solve test.xml --output report.md --verbose
```


### Modes


* `peaceful` — lower thresholds and a fuller report; preserves more potentially useful information
* `standard` — balanced default mode between information retention and compression
* `strict` — higher bar for what counts as a signal; smaller report, more missed values
* `apocalyptic` — maximum selectivity; focuses on the strongest structural signals


`standard` is the recommended starting point. The modes above it trade recall for size: because they raise the minimum value length and the entropy bar, short entity identifiers and low-entropy authorization parameters — exactly the kind of thing worth testing for IDOR — are the first to fall out. A good workflow is to work from a `standard` report and use the more aggressive modes only when a context window forces a smaller input.


### Options


* `--output` / `-o` — destination for the Markdown report (required)
* `--mode` — analysis mode (default: `standard`)
* `--secrets` — how values are written into the report (default: `true`); see below
* `--quiet` — silence all progress output
* `--verbose` — emit per-stage detail on stderr; conflicts with `--quiet`


## Value Masking


By default BurpSqueezer does not write observed values into the report in full. A value that looks like a credential, an address, or an object identifier is replaced with a short fragment, a character count, and a four-digit fingerprint:


```text
<11 chars> [fp:131d]
testpe…nt.com [fp:dd83] (27 chars)
```


The fingerprint is derived from the value itself, so the same value carries the same fingerprint everywhere it appears and two different values are still told apart. Nothing is lost analytically: the value keeps its length, its entropy, its occurrence count, and every endpoint it was seen on.


`--secrets` is a display setting only. Matching, chain detection and scoring always run on the full values in memory, so switching it off changes what you read, not what the tool found.


```bash
# Default: values truncated and fingerprinted
burpsqueezer solve capture.xml --output shareable.md


# Values printed in full
burpsqueezer solve capture.xml --output local.md --secrets false
```


**A report produced with `--secrets false` must not be shared, committed, or sent to an external model.** It contains the credentials and personal data the tool is designed to keep out.


### What is and is not masked


Masked by default:


* Values that look like credentials — tokens, keys, session identifiers
* Email addresses, and object identifiers used as data
* The same, wherever they appear: in paths, query strings, headers, bodies, or in the state-indicator section of the report
* JSON object keys that are data rather than schema, collapsed to `{id}` so that `someone@example.com.plan` is reported as `{id}.plan`
* A value that already appears in the report's own masked output is not re-printed in the clear elsewhere


**Not** masked, by design:


* Hostnames, URL paths, and endpoint structure — this is the analysis, and it is what makes the report useful
* Schema-level field names, which describe the application rather than any one user
* Enumerated values in state indicators, because the whole point of that section is to list the values a field took


One limitation is worth stating plainly: masking is driven by the shape of a value, and a person's name is shaped like ordinary vocabulary. A name that appears nowhere as a masked value may be printed in full. If a capture contains personal data in plain-word fields, review the report before sharing it.


## Output


BurpSqueezer transforms raw Burp Suite XML traffic into a structured and highly compact Markdown representation intended for LLM-based analysis.


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


Paths and field locations that carry a value are normalized. `/api/v3/users/812696` and `/api/v3/users/445190` both appear as `/api/v3/users/{id}`, and the report tracks how many distinct values were seen behind each placeholder. Without this, a capture with thousands of users would produce thousands of near-identical rows and nothing would compress; with it, repetition becomes a signal in itself rather than noise.


BurpSqueezer is **not intended to simply summarize HTTP traffic**. Its goal is to produce a compact, security-oriented representation of the underlying API structure and relationships while removing a significant amount of redundant and low-value data.


The original Burp dump can still be useful for manual verification or retrieving information that was intentionally omitted during compression.


## Relationship with Burp Suite


BurpSqueezer is an independent security research tool and is **not affiliated with, endorsed by, or developed by PortSwigger**.


It does not contain or distribute Burp Suite software.


BurpSqueezer operates on HTTP traffic exported by the user from Burp Suite. The input is user-provided Burp Suite XML data; BurpSqueezer does not interact with or send requests to the target application.


## Development


BurpSqueezer is developed against a test suite of 322 automated tests, including whole-report snapshots that pin the output of the standard and apocalyptic modes. Any change to what the report says shows up as a diff in a snapshot rather than passing silently.


```bash
cargo test
```


## Limitations


This is an experimental security research tool. Results may vary across different Burp collections.


BurpSqueezer is primarily designed for large datasets and applications with meaningful API structure or business logic. Small, highly specialized, or structurally sparse datasets may provide less information for the statistical analysis to work with.


Statistical and heuristic analysis cannot guarantee that every relevant relationship, data flow, or security signal will be identified.


Aggressive compression modes may intentionally discard information in exchange for a smaller output. As noted under [Modes](#modes), the more selective modes can drop short entity identifiers and authorization-related parameters that are worth testing.


Value masking is shape-based. It reliably hides credentials, addresses and object identifiers, but it cannot distinguish a person's name from an ordinary enum value, and it deliberately leaves hosts, paths and structure visible. Review a report before sharing it.


BurpSqueezer is intended to assist human and LLM-based analysis, **not replace manual security testing or verification**.


## Responsible Use


BurpSqueezer is intended for authorized security testing, penetration testing, bug bounty programs, and security research.


Only analyze HTTP traffic that you are authorized to access. Do not use BurpSqueezer with data obtained from systems or applications without appropriate permission.


The author is not responsible for misuse of the software.


## License


See the `LICENSE` file for the terms under which BurpSqueezer is distributed.
