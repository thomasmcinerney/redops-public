"""Smoke test the MCP evidence bridge without contacting a server."""
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))
sys.path.append(str(ROOT / 'report-kit'))
import report


def main():
    import redops.mcp_server as server
    with tempfile.TemporaryDirectory(prefix='mcp-evidence-') as tmp:
        case = Path(tmp)
        report.save(case, {'schema': 1, 'targets': {'box': {}},
                         'stages': [{'target': 'box', 'kind': 'recon'}],
                         'events': [], 'review': None})
        row = {'id': 42, 'engagement_id': 7, 'command': 'probe',
               'output': 'captured text', 'status': 'done', 'actor': 'agent'}
        server._engagement = lambda: 7
        server.tool_results = lambda ip=None, run_id=None, **kwargs: json.dumps(row)
        result = json.loads(server.report_import_run(42, str(case), 'box', 'recon'))
        assert result['evidence_id']
        assert len(report.load(case)['events']) == 2
        assert json.loads(server.report_import_run(42, str(case), 'box', 'recon')) == result
        print('bridge import passed')


if __name__ == '__main__':
    main()
