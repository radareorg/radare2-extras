#!/usr/bin/env python3
"""Exercise asynchronous PCM playback with libao's silent output driver."""
import os
from pathlib import Path
import subprocess

plugin = Path(__file__).resolve().with_name('core_au.dylib' if os.uname().sysname == 'Darwin' else 'core_au.so')
commands = [f'L {plugin}', 'auq?', '?v $?', 'e asm.arch=gb']
for _ in range(30):
    commands += ['auqi 44100 16 2 null', '?v $?', 'auq 0 4096', '?v $?',
                 'auq 0 3', '?v $?', 'auq 0 32772', '?v $?', 'auq-', '?v $?']
commands += ['e asm.arch', 'auqi 44100 16 2 null', 'auq 0 4096']
env = dict(os.environ, R2_NOPLUGINS='1')
result = subprocess.run([os.environ.get('R2', 'r2'), '-N', '-q', '-c', ';'.join(commands),
                         'malloc://32768'], env=env, capture_output=True, text=True, timeout=20)
assert result.returncode == 0, result.stderr
lines = result.stdout.splitlines()
values = [line for line in lines if line.startswith('0x')]
assert values == ['0x1'] + ['0x1', '0x1000', '0x0', '0x0', '0x1'] * 30, result.stdout
assert 'gb' in lines, result.stdout
assert result.stderr.count('PCM length must') == 60, result.stderr
print('PCM queue initialization, playback, bounds, repeated close, and unload: OK')
