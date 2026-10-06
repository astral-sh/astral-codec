"""Repeat the original ZIP suite under selected runtime controls in CI."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time


def snapshot():
    processes = []
    for status_path in Path('/proc').glob('[0-9]*/status'):
        try:
            status = dict(line.split(':', 1) for line in status_path.read_text().splitlines())
            processes.append({
                'pid': int(status_path.parent.name),
                'name': status['Name'].strip(),
                'cpus': status['Cpus_allowed_list'].strip(),
                'cgroup': (status_path.parent / 'cgroup').read_text().strip(),
            })
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return {
        'processes': processes,
        'cgroups': {str(path): path.read_text().strip()
                    for path in Path('/sys/fs/cgroup').glob('*/cpuset.cpus.effective')},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pin-cpu', choices=['true', 'false'], required=True)
    parser.add_argument('--allocator', choices=['adaptive', 'fixed'], required=True)
    parser.add_argument('--profile', choices=['true', 'false'], required=True)
    parser.add_argument('--test', action='store_true')
    arguments = parser.parse_args()
    if not arguments.test and os.environ.get('CODSPEED_PROFILER_ENABLED') != arguments.profile:
        parser.error('--profile must match CODSPEED_PROFILER_ENABLED')
    destination = Path('target/zip-runtime-verify')
    destination.mkdir(parents=True, exist_ok=True)
    affinity = sorted(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else []
    if arguments.pin_cpu == 'true':
        if affinity:
            if max(affinity) < 2:
                raise ValueError(f'Benchmark did not reach reserved CPUs: {affinity}')
            os.sched_setaffinity(0, {max(affinity)})
        elif not arguments.test:
            raise ValueError('Linux CPU affinity is required')
    environment = os.environ.copy()
    if arguments.allocator == 'fixed':
        for key in list(environment):
            if key.startswith('MALLOC_'):
                del environment[key]
        tunables = [value for value in environment.get('GLIBC_TUNABLES', '').split(':')
                    if value and not value.startswith('glibc.malloc.')]
        tunables += ['glibc.malloc.mmap_threshold=33554432', 'glibc.malloc.trim_threshold=67108864']
        environment['GLIBC_TUNABLES'] = ':'.join(tunables)
    metadata = {
        'arguments': vars(arguments),
        'original_affinity': affinity,
        'affinity': sorted(os.sched_getaffinity(0)) if affinity else [],
        'allocator_environment': {key: value for key, value in environment.items()
                                  if key.startswith('MALLOC_') or key == 'GLIBC_TUNABLES'},
        'artifacts': {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in Path('target/codspeed').rglob('*')
                      if path.is_file() and os.access(path, os.X_OK)},
        'before': snapshot(),
    }
    (destination / 'environment.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(json.dumps(metadata), flush=True)
    command = ['python', 'scripts/bench-zip.py', '--compare']
    if arguments.test:
        command.append('--test')
    started = time.monotonic()
    result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=1200)
    elapsed = time.monotonic() - started
    metadata['after'] = snapshot()
    (destination / 'environment.json').write_text(json.dumps(metadata, indent=2) + '\n')
    (destination / 'suite.log').write_text(result.stdout + result.stderr)
    print(result.stdout, end='', flush=True)
    print(result.stderr, end='', flush=True)
    result.check_returncode()
    rows = []
    cases = []
    pending = None
    units = {'ns': 1e-9, 'µs': 1e-6, 'μs': 1e-6, 'us': 1e-6, 'ms': 1e-3, 's': 1}
    for line in result.stdout.splitlines():
        if match := re.fullmatch(r'Isolated comparison: (\w+)\[(.*)\]', line):
            pending = match.groups()
            cases.append(pending)
        elif not arguments.test and pending and f'╰─ {pending[1]} ' in line:
            timings = re.findall(r'([0-9]+(?:\.[0-9]+)?)\s+(ns|µs|μs|us|ms|s)\b', line)
            if len(timings) != 4:
                raise ValueError(f'Missing timings: {line}')
            row = {'operation': pending[0], 'case': pending[1]}
            row.update(zip(['fastest', 'slowest', 'median', 'mean'],
                           [float(value) * units[unit] for value, unit in timings]))
            columns = line.split('│')
            row['samples'] = int(columns[-2].strip())
            row['iterations'] = int(columns[-1].strip())
            rows.append(row)
            pending = None
    if len(cases) != len(set(cases)) or len(cases) != 140:
        raise ValueError(f'Expected 140 distinct cases, got {len(cases)}')
    if not arguments.test and len(rows) != len(cases):
        raise ValueError(f'Missing results: {len(rows)} of {len(cases)}')
    (destination / 'results.json').write_text(json.dumps({'elapsed_seconds': elapsed, 'rows': rows}, indent=2) + '\n')
    print(f'Completed all {len(cases)} cases.', flush=True)


if __name__ == '__main__':
    main()
