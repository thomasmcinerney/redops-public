"""Import an already captured command into an evidence case without running it."""
from __future__ import annotations

import argparse
import json
import re
import shlex
from pathlib import Path

import report


REQUIRED = ('source_system', 'source_engagement', 'source_id', 'command', 'output')


def reproduction_command(command: str) -> str:
    """Copy/paste equivalent for typed HTTP captures; shell commands stay exact."""
    command = command.strip()
    if not re.match(r'^(GET|POST|PUT|PATCH|DELETE|HEAD) https?://', command):
        return command
    verb, _, rest = command.partition(' ')
    url, _, tail = rest.partition(' ')
    if verb in ('GET', 'HEAD'):
        paths = tail.split() if tail else []
        if paths and not all(path.startswith('/') for path in paths):
            return ''
        urls = [url.rstrip('/') + path for path in paths] if paths else [url]
        return '\n'.join('curl -sS --max-time 10 -X ' + verb + ' ' + shlex.quote(item)
                         for item in urls)
    if not tail:
        return ''
    try:
        json.loads(tail)
    except json.JSONDecodeError:
        return ''
    return ('curl -sS --max-time 10 -X ' + verb + ' ' + shlex.quote(url) +
            " -H 'Content-Type: application/json' --data " + shlex.quote(tail))


def import_capture(root: Path, target: str, stage: str, capture: dict) -> str:
    missing = [key for key in REQUIRED if key not in capture or (key != "output" and not capture[key])]
    if missing:
        raise ValueError(f"capture missing: {', '.join(missing)}")
    key = ':'.join(str(capture[k]) for k in REQUIRED[:3])
    reproduce = str(capture.get('reproduce') or reproduction_command(str(capture['command'])))
    with report.case_lock(root):
        data = report.load(root)
        report.stage(data, target, stage)
        prior = next((event for event in data['events']
                      if event.get('kind') == 'command' and event.get('source_key') == key), None)
        if prior:
            if prior['target'] != target or prior['stage'] != stage:
                raise ValueError('capture already imported under another target or stage')
            transcript = root / prior['transcript']
            if transcript.read_text(encoding='utf-8') != str(capture['output']):
                raise ValueError('capture content changed for an existing source id')
            if prior['command'] != str(capture['command']):
                raise ValueError('capture command changed for an existing source id')
            if prior.get('source_status', '') != str(capture.get('status') or ''):
                raise ValueError('capture status changed for an existing source id')
            if prior.get('exit_code') is not None and capture.get('exit_code') is not None and prior['exit_code'] != capture['exit_code']:
                raise ValueError('capture exit code changed for an existing source id')
            if prior.get('reproduce') and prior['reproduce'] != reproduce:
                raise ValueError('reproduction command changed for an existing source id')
            screenshot = root / 'evidence' / f"{prior['id']}-console.png"
            shot_event = next((event for event in data['events']
                               if event.get('kind') == 'screenshot' and
                               event.get('file') == str(screenshot.relative_to(root))), None)
            repaired = not screenshot.is_file()
            metadata_changed = False
            if not prior.get('reproduce') and reproduce:
                prior['reproduce'] = reproduce
                metadata_changed = True
            if prior.get('exit_code') is None and capture.get('exit_code') is not None:
                prior['exit_code'] = capture['exit_code']
                repaired = True
            if shot_event is None:
                report.capture_console(root, data, prior)
            elif repaired:
                report.render_console_image(root, prior)
                shot_event['sha256'] = report.digest(screenshot)
                metadata_changed = True
            if metadata_changed and shot_event is not None:
                data['review'] = None
                report.save(root, data)
            return prior['id']

        event_id = report.ident()
        transcript = root / 'transcripts' / f'{event_id}.txt'
        transcript.parent.mkdir(parents=True, exist_ok=True)
        (root / "evidence").mkdir(parents=True, exist_ok=True)
        transcript.write_text(str(capture['output']), encoding='utf-8')
        event = {
            'id': event_id, 'at': report.now(),
            'actor': str(capture.get('actor') or 'agent'),
            'target': target, 'stage': stage, 'kind': 'command',
            'command': str(capture['command']), 'reproduce': reproduce,
            'cwd': str(capture.get('cwd') or '(captured externally)'),
            'status': 'done', 'transcript': str(transcript.relative_to(root)),
            'sha256': report.digest(transcript),
            'provenance': 'imported_capture', 'source_key': key,
            'source_system': str(capture['source_system']),
            'source_engagement': capture['source_engagement'],
            'source_id': capture['source_id'],
            'source_status': str(capture.get('status') or ''),
            'exit_code': capture.get('exit_code'),
            'source_recorded_at': str(capture.get('recorded_at') or ''),
        }
        data['events'].append(event)
        data['review'] = None
        report.save(root, data)
        report.capture_console(root, data, event)
        return event_id


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('case', type=Path)
    parser.add_argument('capture', type=Path, help='JSON object or array of captured commands')
    parser.add_argument('--target', required=True)
    parser.add_argument('--stage', required=True)
    args = parser.parse_args()
    root = args.case.resolve()
    payload = json.loads(args.capture.read_text(encoding='utf-8'))
    captures = payload if isinstance(payload, list) else [payload]
    for capture in captures:
        print(import_capture(root, args.target, args.stage, capture))


if __name__ == '__main__':
    main()
