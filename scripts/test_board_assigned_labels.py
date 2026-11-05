"""The board distinguishes Portal-assigned addresses from observed hosts."""

import subprocess
import unittest
from pathlib import Path


BOARD = Path(__file__).resolve().parents[1] / "redops" / "static" / "board.html"


class AssignedHostLabelsTest(unittest.TestCase):
    def test_scope_header_and_switcher_keep_unreached_assignments_visible(self):
        html = BOARD.read_text(encoding="utf-8")
        script = html.split("<script>", 1)[1].split("</script>", 1)[0]
        parsed = subprocess.run(["node", "--check", "-"], input=script,
                                text=True, capture_output=True, check=False)
        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        load_targets = "async function loadTargets(){" + script.split(
            "async function loadTargets(){", 1)[1].split("\nasync function loadGraph(){", 1)[0]
        build_switcher = "function buildSwitcher(){" + script.split(
            "function buildSwitcher(){", 1)[1].split("\nfunction syncSwitcher(){", 1)[0]
        probe = """
import assert from 'node:assert/strict';
let targets=[], tnodes={}, reveals={}, engId=116;
const rows=[
  {id:1,ip:'192.0.2.10',status:'identified'},
  {id:2,ip:'172.16.0.10',status:'unidentified'},
  {id:3,ip:'172.16.0.20',status:'rooted'}
];
const sw={innerHTML:'',querySelectorAll:()=>[]};
const nodes={'#s-tgt':{textContent:''},'#s-assigned':{textContent:''},'#switcher':sw};
const $=selector=>nodes[selector];
const esc=value=>String(value);
const api=async()=>rows;
const syncSwitcher=()=>{};
const layoutScope=()=>{};
""" + load_targets + "\n" + build_switcher + "\n" + """
await loadTargets();
assert.equal(nodes['#s-tgt'].textContent,2);
assert.equal(nodes['#s-assigned'].textContent,3);
assert.equal(Object.keys(tnodes).length,3);
assert.match(sw.innerHTML,/172\\.16\\.0\\.10 · not yet reached/);
assert.match(sw.innerHTML,/192\\.0\\.2\\.10/);
console.log('board host labels PASS');
"""
        result = subprocess.run(["node", "--input-type=module", "-"], input=probe,
                                text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("board host labels PASS", result.stdout)
        self.assertIn("assigned · not yet reached", script)
        self.assertNotIn("unknown host", script)


if __name__ == "__main__":
    unittest.main()
