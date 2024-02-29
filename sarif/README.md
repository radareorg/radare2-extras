# SARIF for Radare2

Static Analysis Results Interchange Format (SARIF) Version 2.0

## Description

This plugin for radare2 adds the `sarif` command to the r2 shell which allows to import and export SARIF documents (JSON files) into the current session, allowing the analyst to report and visualize the reported vulnerabilities in a binary using a standard file format.

## Usage

```
[0x00000000]> sarif?
sarif [action] [arguments]
sarif help          - show this help message
sarif import [file] - import sarif info from given file
sarif export [file] - export sarif findings into given file or stdout
sarif script        - generate r2 script with loaded sarif info
sarif reset         - reset all loaded sarif reports
[0x00000000]>
```

## Links

* https://docs.oasis-open.org/sarif/sarif/v2.0/sarif-v2.0.html
