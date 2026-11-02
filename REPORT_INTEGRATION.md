# RedOps report integration

RedOps captures target commands and complete output in its engagement ledger. The bundled `report-kit/` creates a separate evidence case and searchable PDF. The source run ID links each report event back to the engagement.

1. Start a report case with `report-kit/report.py init` and add the target and stage before capture.
2. Set `focus_target` before target work. Run target commands through RedOps MCP with `target_ip` for attribution.
3. At each phase boundary, call `report_import_runs(case_dir, target, stage, target_ip)`. It imports completed focused runs in order, skips runs already assigned to earlier stages, and returns pending run IDs. Use `report_import_run` for a single run.
4. Record observed results, scripts, AI prompts and responses, direct screenshots, and proof values in the report case. CaseHub indexes imported evidence for review.
5. Call `report_build(case_dir)` to check evidence and produce a searchable PDF. Visually review its commands, full output, screenshots, and conclusions before sharing.

The importer is idempotent. A changed command or output under the same source run ID is rejected. Typed HTTP calls receive copy/paste `curl` reproduction text. Full command output remains in both RedOps transcripts and the report case. The generic RedOps Markdown/HTML exporter is also available through `redops export`.
