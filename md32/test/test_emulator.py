#!/usr/bin/env python3
"""Check ESIL results and strict handling of missing boot state."""
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = Path(os.environ.get('MD32_RUNNER', ROOT / 'tools/md32-run'))


def execute(code, *args):
    with tempfile.TemporaryDirectory(prefix='md32-run-') as temp:
        path = Path(temp) / 'code.bin'
        path.write_bytes(bytes.fromhex(code))
        proc = subprocess.run([str(RUNNER), '--image', str(path) + '@0', '--steps', '1', *args],
                              text=True, capture_output=True, check=True)
        return json.loads(proc.stdout)


def scalar():
    # 16- and 32-bit arithmetic shifts, including negative operands and aliasing.
    for word, regs, dest, expected in [
            ('9041', ['r1=0xfffffff0'], 'r1', 0xffffffff),
            ('041d6421', ['r2=0xfffffff0'], 'r1', 0xffffffff),
            ('040ae321', ['r2=0x80000000', 'r3=31'], 'r1', 0xffffffff),
            ('8d21', ['r2=0'], 'r1', 32),
            ('8d21', ['r2=0x80000000'], 'r1', 0),
            ('8d22', ['r2=1'], 'r2', 31),
            ('04196021', ['r2=0xffffffff'], 'r1', 32),
            ('04196021', ['r2=0x80000000'], 'r1', 1),
            ('04196021', ['r2=0x20000000'], 'r1', 2),
            ('20000321', ['r2=0xffffffff', 'r3=1'], 'r1', 1),
            ('20001321', ['r2=0xffffffff', 'r3=1'], 'r1', 0xffffffff),
            ('c421', ['r1=0xffffffff', 'r2=1'], 'r1', 1),
            ('c521', ['r1=0xffffffff', 'r2=1'], 'r1', 0xffffffff),
            ('0407e321', ['r2=0xffffffff', 'r3=7'], 'r1', 0xfffffff9),
            ('0407e321', ['r2=0', 'r3=7'], 'r1', 7)]:
        args = [x for reg in regs for x in ['--reg', reg]]
        out = execute(word, *args)
        assert out['stop_reason'] == 'step_limit', (word, out)
        assert out['completed_steps'] == 1 and out['initialized_registers'][dest] == expected, (word, out)
        assert out['pc'] == len(bytes.fromhex(word)), out
    print('Arithmetic shifts, bit counts, min/max and conditional inversion passed')


def boundaries():
    # Assignment must not count ESIL's destination bookkeeping as a semantic read.
    out = execute('9811')
    assert out['completed_steps'] == 1 and out['initialized_registers']['r1'] == 1
    out = execute('8811')
    assert out['stop_reason'] == 'uninitialized_register_read' and out['fault_register'] == 'r1'
    assert out['completed_steps'] == 0
    out = execute('06400012', '--reg', 'r2=0x1000')
    assert out['stop_reason'] == 'unmapped_data_read' and out['fault_address'] == 0x1000
    out = execute('06400012', '--reg', 'r2=0x1000', '--ram', '0x1000:8')
    assert out['stop_reason'] == 'uninitialized_data_read' and out['fault_address'] == 0x1000
    out = execute('06400012', '--reg', 'r2=0x1000', '--zero', '0x1000:8')
    assert out['completed_steps'] == 1 and out['initialized_registers']['r1'] == 0
    # Store initializes previously unknown RAM; the following load sees its bytes.
    out = execute('0670001206400032', '--steps', '2', '--reg', 'r1=0x12345678',
                  '--reg', 'r2=0x1000', '--ram', '0x1000:8')
    assert out['completed_steps'] == 2 and out['initialized_registers']['r3'] == 0x12345678, out
    assert [e['access'] for e in out['memory_accesses']] == ['write', 'read']
    # Code memory does not silently act as initialized data in a Harvard CPU.
    out = execute('06400012', '--reg', 'r2=0')
    assert out['stop_reason'] == 'unmapped_data_read'
    out = execute('98119822', '--entry', '1')
    assert out['completed_steps'] == 0 and out['stop_reason'] == 'unaligned_instruction_fetch'
    # No invented semantics for unresolved uSIP extensions or delayed branches.
    out = execute('5ef9901a', '--cpu', 'usip')
    assert out['completed_steps'] == 0 and out['stop_reason'] == 'unsupported_instruction_semantics'
    out = execute('a02f80008000', '--reg', 'r15=0')
    assert out['completed_steps'] == 0 and out['stop_reason'] == 'unsupported_delay_slot_execution'
    # An unsupported pair that contains NOP is not silently skipped either.
    out = execute('40002000')
    assert out['completed_steps'] == 0 and out['stop_reason'] == 'unsupported_instruction_semantics'
    print('Uninitialized registers/RAM, unmapped devices, Harvard maps and strict stops passed')


if __name__ == '__main__':
    scalar()
    boundaries()
