import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import sys
import time
from types import SimpleNamespace

root = Path('/home/ubuntu/private/goxdp-template')
sys.path.insert(0, str(root / 'tests/benchmarks'))
import compare


class DropControl(compare.Trial):
    def setup(self):
        self.namespace(self.dut)
        self.namespace(self.source)
        self.pair('p0', self.source, '02:00:00:00:00:01')
        receiver = self.spawn('rx0', [self.args.xdperf, 'run', '--device', 'p0', '--send=false',
                                      '--recv', '--xdp-mode', 'native'], namespace=self.dut)
        self.wait_attached(receiver, self.dut, 'p0', 'rx0')
        self.rx_maps['rx0'] = compare.program_map(compare.attached_program(self.dut, 'p0'), 'rx_stats_map')
        self.link_before = compare.json_command('ip', '-n', self.dut, '-j', '-s', 'link', 'show', 'dev', 'p0')[0]
        self.queue_before = compare.command('ethtool', '-S', 'p0', namespace=self.dut)


signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
args = SimpleNamespace(xdperf=Path('/tmp/goxdp-xdperf'), plugins=Path('/tmp/goxdp-bench-inputs'),
                       counters=root / 'bin/goxdp-perf-counters', cpus=[0, 1, 2, 3],
                       warmup=2, seconds=5, batch_size=1)
assert set(args.cpus).issubset(os.sched_getaffinity(0))
output = root / 'docs/benchmarks/2026-10-22-flow-hash/drop-control'
output.mkdir(exist_ok=False)
script = Path(__file__).read_bytes()
(output / 'control.py').write_bytes(script)
metadata = {'time_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'kernel': platform.uname()._asdict(),
            'args': {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
            'control_sha256': hashlib.sha256(script).hexdigest(),
            'runner_sha256': compare.digest(root / 'tests/benchmarks/compare.py'),
            'xdperf_sha256': compare.digest(args.xdperf), 'counters_sha256': compare.digest(args.counters),
            'plugin_sha256': compare.digest(args.plugins / 'simpleudp.go.wasm'),
            'topology': 'XDPerf source -> one multiqueue veth pair -> XDPerf receiver XDP_DROP; no forwarding program, replication, VXLAN, or CPUMAP'}
(output / 'environment.json').write_text(json.dumps(metadata, indent=2) + '\n')
results = []
try:
    for repeat in range(3):
        case = dict(mode='drop-control', backend='receiver-drop', frame_size=64, fanout=1,
                    workers=4, queues=4, cpu_redirect=False, forward_cpus=[], repeat=repeat)
        directory = output / f'run-{repeat:03d}'
        directory.mkdir()
        trial = DropControl(args, case, directory)
        try:
            result = trial.run()
            results.append(result)
            (directory / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            (output / 'runs.json').write_text(json.dumps(results, indent=2) + '\n')
            print(repeat, result['offered_pps'], result['delivered_pps'], result['loss_fraction'], flush=True)
        finally:
            trial.close()
finally:
    if 'SUDO_UID' in os.environ:
        for path in [output, *output.rglob('*')]:
            os.chown(path, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))
