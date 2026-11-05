# Report evidence kit

The report kit records exact commands, full output, AI prompts and responses, scripts, screenshots, proof values, and their source run IDs. It builds a searchable PDF with selectable command text and full captured output. It is independent of any assessment provider or template.

## Start a case

```sh
python report-kit/report.py init ./case --title "Authorized assessment" --scope "Assigned systems"
python report-kit/report.py target ./case --id web01 --name "Web 01" --ip 192.0.2.10 --role web --objective "Document access" --summary "Initial assessment"
python report-kit/report.py stage ./case --target web01 --kind recon --summary "Initial discovery" --analysis "Observed service responses"
```

Run `python report-kit/report.py <command> --help` for the exact options. Use `run` or `tty` to capture live commands, `log` for browser and AI activity, `code` for scripts, `screenshot` for direct images, and `proof` for exact proof values. The case lock lets multiple workers add evidence without losing one another's events.

For RedOps-controlled target actions, import captured runs into the case with `report_import_runs` or `report_import_run`. The importer preserves the original command, complete output, source engagement and run ID, and rejects changed reimports. Typed HTTP actions receive a copy/paste `curl` reproduction command.

For browser chatbot scenarios captured by `webchat_capture.py`, import the private manifest with `python report-kit/webchat_import.py ./case ./private/lane-01-capture/manifest.json --target chat --stage recon`. Each completed action becomes a browser event with exact input, widget output, raw network transcript, and a direct screenshot. Reimporting the same run is safe; changed evidence under an existing source ID is rejected. Keep the original manifest and uploads with the case evidence.

## Build and review

```sh
python report-kit/report.py check ./case
python report-kit/report.py build ./case
python report-kit/report.py review ./case --checked
python report-kit/report.py package ./case --practice
```

The build checks case evidence and PDF text. By default it includes full captured output; screenshots rendered from transcripts are supplemental to direct screenshots. Review the PDF visually before packaging or sharing it. The general RedOps exporter remains available for quick Markdown and HTML engagement reports.

See [the integration guide](../REPORT_INTEGRATION.md) for the RedOps bridge. The Grok supervisor and generic agent guide are under `grok/`.
