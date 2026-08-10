# Validation Record

## Automated detection tests

The test suite covers:

- Complete five-finding attack-chain detection
- Authentication grouping by source, user, and host
- Benign process exclusion
- Internal network connection exclusion
- Sensitive archive staging
- EVTX XML normalization
- Unsupported and malformed input handling
- Dashboard case data and filter controls
- Conservative disposition when only one suspicious signal exists

Run the suite with:

```powershell
python -m unittest discover -s tests -v
```

## EVTX compatibility check

The parser was exercised against the `security.evtx` fixture from the official `python-evtx` project. It parsed all 2,261 records and normalized the first and last events without an exception.

Fixture source: <https://github.com/williballenthin/python-evtx/tree/master/tests/data>

## Collector safety check

`Export-SocTelemetry.ps1` and `verify.ps1` are parsed before release with the PowerShell abstract syntax tree parser. The collector only calls `Get-WinEvent`, normalizes selected fields, and writes to the operator-selected output path. It does not modify audit policy, log configuration, endpoint services, or security controls.

## Continuous integration

GitHub Actions installs the project with EVTX support, runs the full test suite, and generates JSON, Markdown, and HTML reports on every push and pull request.
