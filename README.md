# BurpSqueezer

Turn Burp Suite XML dumps into LLM-optimized Markdown reports for security analysis.

## Philosophy

BurpSqueezer is designed as a universal tool with no hardcoded endpoints. It adapts to any API structure through statistical analysis rather than assuming specific patterns. The tool works best with large request dumps — performance and accuracy may degrade on smaller datasets.

## Features

- **Universal Analysis**: No hardcoded patterns or endpoint assumptions
- **Noise Filtering**: Statistical and heuristic-based noise reduction
- **Data Flow Tracking**: Identifies value propagation across requests
- **LLM-Optimized Output**: Compact Markdown format designed for AI analysis
- **Multiple Modes**: Adjustable selectivity for different use cases

## Installation

```bash
cargo install --path .
```

## Usage

```bash
burpsqueezer solve input.xml --output report.md --mode standard
```

### Modes

- `peaceful` — lower thresholds, fuller report, more tolerance for weak signal
- `standard` — balanced default mode
- `apocalyptic` — maximum selectivity, essentially core signal only

### Options

- `--output` — destination for the Markdown report (required)
- `--mode` — analysis mode (default: standard)
- `--quiet` — silence all progress output
- `--verbose` — emit per-stage detail

## Example

```bash
# Basic usage
burpsqueezer solve burp_dump.xml --output analysis.md

# Strict mode for focused analysis
burpsqueezer solve large_dump.xml --output focused.md --mode apocalyptic

# Verbose output for debugging
burpsqueezer solve test.xml --output report.md --verbose
```

## Note

This is an experimental tool. While functional, results may vary across different Burp collections. The tool is designed for large-scale security research and may not perform optimally on small or specialized datasets.