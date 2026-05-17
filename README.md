# BioRobot

A command-line tool for analyzing Windows PE binaries,I originally built this a while back and recently brought it back to life
The name was inspired by [Kung Fu Junkie](https://www.youtube.com/watch?v=fFv-_bejYOQ).

## Requirements

- [.NET 8 SDK](https://dotnet.microsoft.com/download)

## Build & run

```bash
dotnet build
dotnet run -- scan "C:\path\to\file.exe"
```

You can also run the built executable directly (`BioRobot.exe`) from `bin/Debug/net8.0/`

## Commands

| Command | Description |
|---------|-------------|
| `scan` | Basic file info: size, hashes, architecture, sections, imports |
| `strings` | Extract readable ASCII/Unicode strings from a binary |
| `pack` | Packer detection and per-section entropy analysis |
| `analyze` | Full report: sections, imports, entropy, strings, packer hints, risk score |

### Options (analyze)

- `--json` — export results as JSON
- `-o <path>` — output file for JSON export
- `--no-strings` — skip string extraction

## Examples

```
biorobot scan notepad.exe
biorobot strings sample.exe --limit 200
biorobot pack sample.exe
biorobot analyze sample.exe --json -o report.json
```

## Safety note

BioRobot only **reads** files, it does not execute them. For unknown or suspicious samples, use an isolated environment (e.g. a VM) before analysis

## Disclaimer

BioRobot is provided for **educational and research purposes only**. You are responsible for ensuring that your use of this software complies with applicable laws and regulations in your jurisdiction.

Analysis output (including risk scores, packer detection, and string extraction) is **heuristic** and may be incomplete or incorrect. Do not treat results as a definitive malware verdict or substitute for professional security tooling.

This software is offered **as is**, without warranty of any kind. The author is not liable for any damage, data loss, or legal issues arising from the use or misuse of this project—including analysis of malicious files on systems that are not properly isolated.
