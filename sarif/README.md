# SARIF for Radare2

Static Analysis Results Interchange Format (SARIF) Version 2.0

## Description

This plugin for radare2 adds the `sarif` command to the r2 shell which allows to import and export SARIF documents (JSON files) into the current session, allowing the analyst to report and visualize the reported vulnerabilities in a binary using a standard file format.

## Usage

```
[0x00000000]> sarif?
sarif [action] [arguments]
sarif -h, help              - show this help message (-h)
sarif -a, add [r] [c]       - add a new sarif finding
sarif -aw,-ae,-an [r] [c]   - add warning, error or note
sarif -i, import [file]     - import sarif info from given file
sarif -j, json              - print the spotted findings as json to stdout
sarif -r, r2|script         - generate r2 script with loaded sarif info
sarif -R, reset             - reset reported findings list
sarif -l, rules ([file])    - list or load rules from file
[0x00000000]>
```

First you need to load the rules that you plan to report as findings:

```
[0x00000000]> sarif -l rule.json
```

Those can be listed with `sarif -l` (note that there's no argument here). At this point you are ready to report your first finding!

* Seek to the offset where the vulnerability is spotted
* Run `sarif -aw rules.mastg-android-insecure-random-use Do not use this API`

You can now export the sarif file in json using the following command:

```
[0x00000000]> sarif -j > reports.json
```

Alternatively you can combine multiple finding documents and load that info inside r2:

```
[0x00000000]> sarif -i report0.json
[0x00000000]> sarif -i report1.json
[0x00000000]> .sarif -r
```

You will have flags prefixed with `sarif.` to spot them in the binary. `f~^sarif`

## Links

* https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning?learn=code_security_integration
* https://github.com/microsoft/sarif-tutorials/
* https://docs.oasis-open.org/sarif/sarif/v2.0/sarif-v2.0.html
* https://sarifweb.azurewebsites.net/#Specification
* https://github.blog/2024-02-14-fixing-security-vulnerabilities-with-ai/
