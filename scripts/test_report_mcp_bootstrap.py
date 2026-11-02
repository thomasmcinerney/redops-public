"""Fresh RedOps engagement to REPORT case, without a live server."""

import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'report-kit'))
import report

server = importlib.import_module('redops.mcp_server')


@pytest.fixture
def isolated_engagement(tmp_path, monkeypatch):
    monkeypatch.setattr(server, '__file__', str(tmp_path / 'redops' / 'mcp_server.py'))
    monkeypatch.setattr(server, '_engagement', lambda: 7)
    monkeypatch.setattr(server, 'find_target',
                        lambda ip: {'id': 1, 'ip': ip} if ip == '192.0.2.10'
                        else (_ for _ in ()).throw(ValueError('not an assigned target')))
    return tmp_path / 'data' / 'work' / '7' / 'report-case'


def test_fresh_case_target_stage_narrative_and_retry(isolated_engagement):
    root = isolated_engagement
    created = json.loads(server.report_case_init('Practice', '192.0.2.10 only'))
    assert created == {'case_dir': str(root), 'engagement_id': 7, 'created': True}
    assert json.loads(server.report_case_init('Practice', '192.0.2.10 only'))['created'] is False
    assert report.load(root)['redops_engagement_id'] == 7

    target = json.loads(server.report_target_add(
        'box', 'Assigned box', '192.0.2.10', 'web', 'Record foothold',
        'Testing in progress', unscored=True))
    assert target['created'] is True
    assert json.loads(server.report_target_add(
        'box', 'Assigned box', '192.0.2.10', 'web', 'Record foothold',
        'Testing in progress', unscored=True))['created'] is False
    server.report_stage_add('box', 'recon', 'Initial recon', 'Observed reachable service')
    server.report_stage_revise('box', 'recon', 'Port 80 open', 'HTTP responded')
    server.report_narrative_set('box', 'HTTP service', 'Observed weakness',
                              'Ordered steps', 'Observed access', 'Exact commands')
    case = report.load(root)
    assert case['targets']['box']['report']['reproduction'] == 'Exact commands'
    assert case['stages'][0]['analysis'] == 'HTTP responded'


def test_bootstrap_rejects_cross_engagement_and_unassigned_target(isolated_engagement):
    root = isolated_engagement
    server.report_case_init('Practice', '192.0.2.10 only')
    with pytest.raises(ValueError, match='different metadata'):
        server.report_case_init('Different', '192.0.2.10 only')
    with pytest.raises(ValueError, match='not an assigned target'):
        server.report_target_add('outside', 'Outside', '198.51.100.3',
                               'web', 'None', 'None')

    case = report.load(root)
    case['redops_engagement_id'] = 8
    report.save(root, case)
    with pytest.raises(ValueError, match='another engagement'):
        server.report_target_add('box', 'Assigned box', '192.0.2.10',
                               'web', 'Record foothold', 'Testing in progress')


def test_scored_stage_still_requires_evidence_before_advancing(isolated_engagement):
    root = isolated_engagement
    server.report_case_init('Practice', '192.0.2.10 only')
    server.report_target_add('box', 'Assigned box', '192.0.2.10', 'web',
                           'Record proof', 'Testing in progress')
    server.report_stage_add('box', 'recon', 'Initial recon')
    with pytest.raises(ValueError, match='needs text evidence'):
        server.report_stage_add('box', 'validation', 'Validation')
    with report.case_lock(root):
        case = report.load(root)
        report.add_event(root, case, {'target': 'box', 'stage': 'recon',
                                    'kind': 'note', 'text': 'Observed HTTP 200'})
    with pytest.raises(ValueError, match='direct screenshot'):
        server.report_stage_add('box', 'validation', 'Validation')
