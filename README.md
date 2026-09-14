# BurpSqueezer

Turn Burp Suite XML dumps into LLM-optimized Markdown reports for security analysis.

## Philosophy

BurpSqueezer is designed as a universal tool with no hardcoded endpoints. It adapts to any API structure through statistical analysis rather than assuming specific patterns. The tool works best with large request dumps — performance and accuracy may degrade on smaller datasets.

A key goal of BurpSqueezer is to transform large and potentially overwhelming HTTP request dumps into highly compact representations while preserving useful structural, relational, and data-flow information. This makes the resulting reports practical for both human analysis and LLM-based security analysis, even when the original dataset would be too large or inefficient to provide directly to an LLM.

**Important:** BurpSqueezer is designed specifically for APIs and applications with meaningful business logic. HTTP request dumps from simple websites with little or no backend logic may provide significantly less useful results, as there may be insufficient structure or relationships for BurpSqueezer to analyze effectively.


## Features

* **Universal Analysis**: No hardcoded patterns or endpoint assumptions
* **High Compression**: Reduces large HTTP request dumps into significantly smaller reports while preserving relevant analytical information
* **Noise Filtering**: Statistical and heuristic-based noise reduction
* **Data Flow Tracking**: Identifies value propagation across requests
* **LLM-Optimized Output**: Compact Markdown format designed for AI analysis
* **Multiple Modes**: Adjustable selectivity for different use cases

## Installation

```bash
cargo install --path .
```

## Usage

```bash
burpsqueezer solve input.xml --output report.md --mode standard
```

### Modes

* `peaceful` — lower thresholds, fuller report, more tolerance for weak signal
* `standard` — balanced default mode
* `apocalyptic` — maximum selectivity, essentially core signal only

### Options

* `--output` — destination for the Markdown report (required)
* `--mode` — analysis mode (default: standard)
* `--quiet` — silence all progress output
* `--verbose` — emit per-stage detail

## Example

```bash
# Basic usage
burpsqueezer solve burp_dump.xml --output analysis.md

# Strict mode for focused analysis
burpsqueezer solve large_dump.xml --output focused.md --mode apocalyptic

# Verbose output for debugging
burpsqueezer solve test.xml --output report.md --verbose
```

## Output

BurpSqueezer transforms raw Burp XML data into a structured and highly compact Markdown report optimized for both human review and LLM-based security analysis.

A key goal of BurpSqueezer is to significantly reduce the size of large HTTP request dumps while preserving the most relevant structural and relational information for further analysis. This allows large datasets that may be impractical to provide directly to an LLM to be reduced into much smaller reports that can be used as context for a wide range of LLMs.

The generated report can contain information about:

* API endpoints and their relationships
* Request and response patterns
* Parameter and value propagation
* Data flows between requests
* Statistical relationships between endpoints
* Relevant structural signals after noise reduction

The exact output depends on the input dataset and selected analysis mode.

BurpSqueezer is not intended to simply summarize HTTP traffic. Its goal is to produce a compact, security-oriented representation of the underlying API structure and relationships while removing a significant amount of redundant and low-value data.


## Relationship with Burp Suite

BurpSqueezer is an independent security research tool and is not affiliated with, endorsed by, or developed by PortSwigger.

It does not contain or distribute Burp Suite software. BurpSqueezer operates on HTTP data exported by the user from Burp Suite.

## Limitations

This is an experimental tool. While functional, results may vary across different Burp collections. The tool is designed for large-scale security research and may not perform optimally on small or highly specialized datasets.

Statistical analysis cannot guarantee that every relevant relationship or security signal will be identified. BurpSqueezer is intended to assist human analysis rather than replace manual security testing.

## Responsible Use

BurpSqueezer is intended for authorized security testing, penetration testing, bug bounty programs, and security research.

Only analyze HTTP traffic that you are authorized to access. Do not use BurpSqueezer against systems or data without appropriate permission.

The author is not responsible for misuse of the software.

## License

See the `LICENSE` file for the terms under which BurpSqueezer is distributed.
