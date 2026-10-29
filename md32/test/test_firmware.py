#!/usr/bin/env python3
"""Validate all three supplied images and reproduce the boot limitations."""
import contextlib
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from analyze_firmware import analyze, REGIONS

BUNDLE = ROOT / 'third_party/v2/r2pkg'


def main():
    if not (BUNDLE / 'data/functions.csv').exists():
        print('v2 bundle absent; skipping optional three-image analysis')
        return
    with tempfile.TemporaryDirectory(prefix='md32-analysis-') as temp:
        with contextlib.redirect_stdout(io.StringIO()):
            result = analyze(BUNDLE, Path(temp), ROOT / 'test/test_md32')
        assert result['functions'] == 1301
        assert [i['functions'] for i in result['images']] == [271, 857, 173]
        assert sum(i['instruction_records'] for i in result['images']) == 125197
        assert sum(i['code_instructions'] for i in result['images']) == 125197
        assert sum(i['non_vector_instructions'] for i in result['images']) == 124941
        assert all(not i['metadata_count_mismatches'] for i in result['images'])
        assert all(i['long_string_candidates'] == 0 for i in result['images'])
        assert result['string_pointer_candidates'] == []
        vectors = result['vectors']
        assert vectors[0]['address'] == 0x400e0000
        assert vectors[0]['encoding'] == 0x400fd5c0
        assert [v['index'] for v in vectors if v['target'] is None] == [0, 8]
        assert sum(v['target'] == 0x400e08d0 for v in vectors) == 238
        assert sum(v['self_loop'] for v in vectors) == 12
        assert all(v['at_instruction_boundary'] for v in vectors if v['target'] is not None)
        jumps = [f for f in result['flows'] if f['mnemonic'].startswith('j ')]
        assert len(jumps) == 342 and all(f['target_is_boundary'] for f in jumps)
        assert len(result['flows']) == 1278
        assert sum(not f['target_is_boundary'] for f in result['flows']) == 6
        cases = [('sec0', ['--vector'], 0x400e0000, '.word 0x400fd5c0', 0,
                  'unsupported_instruction_semantics'),
                 ('ddr', ['--entry', '0x1ca74264'], 0x1ca74264, '.word 0x003ac808', 0,
                  'unsupported_instruction_semantics'),
                 ('sec0', ['--entry', '0x400e0048'], 0x400e0048, 'j 0x400e08d0', 1,
                  'unsupported_instruction_semantics'),
                 ('sec0', ['--entry', '0x400e0008'], 0x400e0008, 'j 0x400e0008', 1,
                  'unconditional_self_loop')]
        for region, extra, address, instruction, completed, reason in cases:
            proc = subprocess.run([str(ROOT / 'tools/md32-run'), '--cpu', 'usip', '--image',
                                   str(BUNDLE / ('bin/usip_%s.bin' % region)) + '@%#x' % REGIONS[region],
                                   *extra], capture_output=True, text=True, check=True)
            report = json.loads(proc.stdout)
            assert report['completed_steps'] == completed
            assert report['stop_reason'] == reason
            assert report['trace'][0]['pc'] == address
            assert report['trace'][0]['instruction'] == instruction
    print('All 1301 functions / 125197 records, executable vectors, strings and boot probes passed')


if __name__ == '__main__':
    main()
