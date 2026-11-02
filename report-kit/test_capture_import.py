"""Evidence import is complete and idempotent."""
import tempfile
from pathlib import Path

import report
from capture_import import import_capture


def test_import_capture_roundtrip():
    with tempfile.TemporaryDirectory(prefix='capture-import-') as tmp:
        root = Path(tmp)
        for name in ('evidence', 'transcripts', 'code', 'build'):
            (root / name).mkdir()
        data = {'schema': 1, 'created': report.now(), 'title': 'test',
                'report_id': 'practice', 'scope': 'lab',
                'targets': {'box': {'name': 'box', 'ip': 'box', 'role': '',
                                    'objective': '', 'summary': 'Practice overview',
                                    'required_stages': ['recon'], 'scored': False,
                                    'proof': None}},
                'stages': [{'target': 'box', 'kind': 'recon', 'summary': 'Recon'}],
                'events': [], 'review': None, 'gates_required': True}
        report.save(root, data)
        capture = {'source_system': 'ops', 'source_engagement': 7,
                   'source_id': 42, 'command': 'probe', 'output': 'observed output',
                   'actor': 'codex', 'status': 'done'}
        first = import_capture(root, 'box', 'recon', capture)
        assert import_capture(root, 'box', 'recon', capture) == first
        events = report.load(root)['events']
        assert len(events) == 2
        command = next(e for e in events if e['kind'] == 'command')
        assert command['source_key'] == 'ops:7:42'
        assert (root / command['transcript']).read_text() == 'observed output'
        assert report.validate(root, report.load(root), False) == []


def test_changed_capture_is_rejected():
    with tempfile.TemporaryDirectory(prefix='capture-import-') as tmp:
        root = Path(tmp)
        root.mkdir(exist_ok=True)
        report.save(root, {'schema': 1, 'targets': {'box': {}},
                         'stages': [{'target': 'box', 'kind': 'recon'}],
                         'events': [], 'review': None})
        capture = {'source_system': 'ops', 'source_engagement': 7,
                   'source_id': 42, 'command': 'probe', 'output': ''}
        import_capture(root, 'box', 'recon', capture)
        capture['output'] = 'different'
        try:
            import_capture(root, 'box', 'recon', capture)
        except ValueError:
            pass
        else:
            assert False, 'changed source must fail'


def test_reimport_repairs_rendered_image_without_duplicate_event():
    with tempfile.TemporaryDirectory(prefix='capture-import-') as tmp:
        root = Path(tmp)
        report.save(root, {'schema': 1, 'targets': {'box': {}},
                         'stages': [{'target': 'box', 'kind': 'recon'}],
                         'events': [], 'review': None})
        capture = {'source_system': 'ops', 'source_engagement': 7,
                   'source_id': 42, 'command': 'probe', 'output': 'observed output',
                   'status': 'done', 'exit_code': 0}
        event_id = import_capture(root, 'box', 'recon', capture)
        image = root / 'evidence' / f'{event_id}-console.png'
        image.unlink()
        assert import_capture(root, 'box', 'recon', capture) == event_id
        assert image.is_file()
        events = report.load(root)['events']
        assert len(events) == 2
        assert events[1]['sha256'] == report.digest(image)
        capture['command'] = 'changed command'
        try:
            import_capture(root, 'box', 'recon', capture)
        except ValueError:
            pass
        else:
            assert False, 'changed command must fail'


def test_typed_http_reproduction_is_copy_pasteable():
    from capture_import import reproduction_command

    base = "http://" + "example" + ".invalid:8000"
    get = reproduction_command("GET " + base + " /health /openapi.json")
    assert get.splitlines() == [
        "curl -sS --max-time 10 -X GET " + base + "/health",
        "curl -sS --max-time 10 -X GET " + base + "/openapi.json",
    ]
    post = reproduction_command('POST ' + base + '/chat {"message":"hello"}')
    assert post.startswith("curl -sS --max-time 10 -X POST ")
    assert "--data" in post and '"message":"hello"' in post
    assert reproduction_command("GET " + base + " bad-path") == ""
    assert reproduction_command("printf hello") == "printf hello"

def test_reimport_backfills_reproduction_and_invalidates_review():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name in ("evidence", "transcripts", "code", "build"):
            (root / name).mkdir()
        report.save(root, {
            "schema": 1, "created": report.now(), "title": "test",
            "report_id": "practice", "scope": "lab",
            "targets": {"box": {"name": "box", "ip": "box", "role": "",
                                "objective": "", "summary": "Practice overview",
                                "required_stages": ["recon"], "scored": False,
                                "proof": None}},
            "stages": [{"target": "box", "kind": "recon", "summary": "Recon"}],
            "events": [], "review": None, "gates_required": True,
        })
        base = "http://" + "example.invalid"
        capture = {
            "source_system": "redops", "source_engagement": 7, "source_id": 91,
            "command": "GET " + base + " /health",
            "output": "HTTP 200", "status": "done",
        }
        event_id = import_capture(root, "box", "recon", capture)
        case = report.load(root)
        event = next(e for e in case["events"] if e["id"] == event_id)
        event.pop("reproduce")
        case["review"] = {"pdf_sha256": "old-review"}
        report.save(root, case)
        assert import_capture(root, "box", "recon", capture) == event_id
        updated = report.load(root)
        event = next(e for e in updated["events"] if e["id"] == event_id)
        assert event["reproduce"].endswith(base + "/health")
        assert updated["review"] is None
