# Dalamud Plugin Audits

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![AI-DECLARATION: copilot](https://img.shields.io/badge/䷼%20AI--DECLARATION-copilot-fee2e2?labelColor=fee2e2)](https://ai-declaration.md)

Tools to audit closed source, obstructed or encrypted FFXIV Dalamud plugins.

This project contains all findings and allows anyone to fact-check them by
decompiling and reverse engineering the binaries back to source code.

## Setup

Requires the .NET 8 SDK (or newer). Works the same on Windows, Linux and macOS.

```sh
# Checks the plugin builds you placed in plugins/
dotnet build PluginAudits.slnx -c Release
dotnet run --project PluginAudits.Cli -- verify
```

The audited plugins are never downloaded, redistributed or linked by this project: sourcing them is up to the
auditor. `plugins/SHA256SUMS` lists each build's hash and where to place it; `verify` confirms your copy is
the one the findings describe.

To read a verified build, decompile it in-process with the ILSpy engine:

```sh
# Decompile Echo's plugin to decompiled/Echo/0.8.4/
dotnet run --project PluginAudits.Cli -- decompile Echo/0.8.4
```

`decompile` refuses builds that don't match `SHA256SUMS`, and warns when a DLL is protected by .NET Reactor:
those need `drdecrypt` (`PluginAudits.DailyRoutines`, for DailyRoutines and NyaDraw) or `pfrdecrypt`
(`PluginAudits.PFRadar`) to be readable:

```sh
dotnet run --project PluginAudits.DailyRoutines -c Release -- plugins/DailyRoutines/2.2.3.3/latest.zip -o decrypted/DailyRoutines/2.2.3.3
dotnet run --project PluginAudits.PFRadar -c Release -- plugins/PFRadar/1.5.0.7/latest.zip -o decrypted/PFRadar/1.5.0.7
```

## Findings

`findings/<plugin>/<version>.json` lists what was found in a build, one plain description per finding, each backed
by evidence: a short snippet that must appear in a given file of the tool's output. `check` verifies your build against
the listed hashes, then every piece of evidence against your own output, so no description has to be taken on trust:

```sh
dotnet run --project PluginAudits.PFRadar -c Release -- plugins/PFRadar/1.5.0.7/latest.zip -o decrypted/PFRadar/1.5.0.7
dotnet run --project PluginAudits.Cli -- check findings/PFRadar/1.5.0.7.json
```
