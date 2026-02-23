# AuditNpm

A .NET global tool that runs `npm audit`, parses the JSON output, and exits with a non-zero code when vulnerabilities are found at or above a configurable severity threshold.

## Install

```
dotnet tool install -g AuditNpm
```

## Usage

```
audit-npm [directory] [options]
```

| Option | Description |
|---|---|
| `-t, --target-directory` | Directory containing `package.json` (default: current directory) |
| `-s, --severity` | Threshold: `critical`, `high`, `moderate`, `low` (default: `moderate`) |
| `-i, --ignore` | Comma-separated CVE IDs to ignore |
| `-c, --config` | Config file path (default: `audit-npm.config.json` in target directory) |

### Examples

Run against the current directory with default settings:

```
audit-npm
```

Run against a specific directory, only failing on high or critical:

```
audit-npm -t ./my-app -s high
```

Ignore specific vulnerabilities by CVE ID:

```
audit-npm -i CVE-2021-23337,CVE-2024-29041
```

Pass the directory as a positional argument:

```
audit-npm ./my-app
```

## Config file

Create an `audit-npm.config.json` in your project directory:

```json
{
  "severity": "moderate",
  "ignore": [
    "CVE-2021-23337"
  ]
}
```

JSON comments and trailing commas are supported.

CLI `--severity` overrides the config file value. CLI `--ignore` is additive with the config file list.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No vulnerabilities found above the severity threshold (or all were ignored) |
| `1` | One or more unignored vulnerabilities found at or above the threshold |

## Ignoring vulnerabilities

Use CVE IDs to ignore known vulnerabilities. A vulnerability is only ignored if **all** of its associated CVE IDs are in the ignore list. If a package has multiple advisories and only some are ignored, it will still be reported.

## Building from source

Requires .NET 10 SDK.

```
dotnet build src --configuration Release
dotnet test --solution src/AuditNpm.slnx
```
