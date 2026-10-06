"""Collect diagnostic hardware counters for repeated, unchanged ZIP benchmarks."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test', action='store_true')
    parser.add_argument('--huge-pages', choices=['true', 'false'], default='false')
    arguments = parser.parse_args()
    destination = Path('target/zip-counter-study')
    destination.mkdir(parents=True, exist_ok=True)
    binary = Path('target/codspeed/walltime/zip-codec/comparison')
    environment = os.environ.copy()
    environment['GLIBC_TUNABLES'] = 'glibc.malloc.mmap_threshold=33554432:glibc.malloc.trim_threshold=67108864'
    if arguments.huge_pages == 'true':
        environment['GLIBC_TUNABLES'] += ':glibc.malloc.hugetlb=1'
    environment['CODSPEED_CARGO_WORKSPACE_ROOT'] = str(Path.cwd())
    if hasattr(os, 'sched_getaffinity'):
        os.sched_setaffinity(0, {max(os.sched_getaffinity(0))})
    elif not arguments.test:
        raise ValueError('Linux CPU affinity is required')
    metadata = {
        'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        'affinity': sorted(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else [],
        'profile': os.environ.get('CODSPEED_PROFILER_ENABLED'),
        'huge_pages': arguments.huge_pages,
    }
    perf = None
    if not arguments.test:
        candidates = [shutil.which('perf'), *sorted(Path('/usr/lib').glob('linux-tools-*/perf'))]
        for candidate in candidates:
            if candidate and subprocess.run([str(candidate), '--version'], capture_output=True, timeout=10).returncode == 0:
                perf = str(candidate)
                break
        if perf is None:
            raise ValueError('No working perf executable on the macro runner')
        metadata['perf'] = perf
    (destination / 'environment.json').write_text(json.dumps(metadata, indent=2) + '\n')
    cases = [
        ('open', 'mixed-package-64-entries/Stored/astral_async_zip', 512),
        ('encode', 'many-small-1024-entries/Stored/zip', 16),
        ('open', 'many-small-1024-entries/Stored/zip-codec', 64),
    ]
    results = []
    for repetition in range(1 if arguments.test else 12):
        # Alternate order to distinguish case-specific effects from drift.
        for index in range(len(cases)) if repetition % 2 == 0 else reversed(range(len(cases))):
            operation, case, samples = cases[index]
            prefix = destination / f'{repetition}-{index}'
            pattern = rf'::{operation}(\[|::){re.escape(case)}(\]|$)'
            command = ['cargo', 'codspeed', 'run', '-p', 'zip-codec', '--bench', 'comparison', '-m', 'walltime', '--', pattern]
            if arguments.test:
                command += ['--test']
            else:
                command += ['--sample-size', '32', '--sample-count', str(samples), '--min-time', '0']
                command = ['timeout', '--kill-after=10s', '180s', perf, 'stat', '-x', ';', '-o', str(prefix.with_suffix('.perf')),
                           '-e', 'task-clock,cycles,instructions,cache-references,cache-misses,minor-faults,context-switches,cpu-migrations',
                           '--', *command]
            started = time.monotonic_ns()
            memory = []
            with subprocess.Popen(command, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
                try:
                    output, errors = process.communicate(timeout=1)
                except subprocess.TimeoutExpired:
                    # One snapshot per process verifies whether the experimental
                    # allocator setting actually obtained huge pages.
                    for path in Path('/proc').glob('[0-9]*/comm'):
                        try:
                            if path.read_text().strip() == 'comparison':
                                memory.append({'pid': int(path.parent.name),
                                               'smaps_rollup': (path.parent / 'smaps_rollup').read_text()})
                        except (FileNotFoundError, ProcessLookupError, PermissionError):
                            continue
                    try:
                        output, errors = process.communicate(timeout=180)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate()
                        raise
                result = subprocess.CompletedProcess(command, process.returncode, output, errors)
            finished = time.monotonic_ns()
            prefix.with_suffix('.log').write_text(result.stdout + result.stderr)
            result.check_returncode()
            if case not in result.stdout:
                raise ValueError(f'No benchmark matched {case}: {result.stdout}')
            if not arguments.test and '│' not in result.stdout:
                raise ValueError(f'No timed samples for {case}: {result.stdout}')
            row = {'repetition': repetition, 'case_index': index, 'operation': operation,
                   'case': case, 'samples': samples, 'sample_size': 32,
                   'start_ns': started, 'finish_ns': finished, 'output': result.stdout}
            row['memory'] = memory
            results.append(row)
            (destination / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
            print(json.dumps(row), flush=True)
    # The action finalizes these after this command exits; the next workflow step
    # copies the profile from these observed paths.
    (destination / 'profile-folders.json').write_text(json.dumps(
        [str(path) for path in Path('/tmp').glob('profile.*.out')]
    ) + '\n')


if __name__ == '__main__':
    main()
