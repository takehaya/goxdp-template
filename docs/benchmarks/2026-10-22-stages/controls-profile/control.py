import json
import copy
import os
from pathlib import Path
import signal
import sys
import time
from types import SimpleNamespace

root = Path('/home/ubuntu/private/goxdp-template')
sys.path.insert(0, str(root / 'tests/benchmarks'))
import compare
from stages import ProfileTrial

signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
output = root / 'docs/benchmarks/2026-10-22-stages/controls-profile'
output.mkdir(exist_ok=False)
args = SimpleNamespace(binary=root / 'bin/goxdp', counters=root / 'bin/goxdp-perf-counters',
                       xdperf=Path('/tmp/goxdp-xdperf'), plugins=Path('/tmp/goxdp-bench-inputs'),
                       cpus=[0, 1, 2, 3], forward_cpus=[8, 9, 10, 11],
                       batch_size=1, flows=64, warmup=2, seconds=10, profile=True, pps=400000)
metadata = dict(time_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                args={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
                binary_sha256=compare.digest(args.binary), xdperf_sha256=compare.digest(args.xdperf),
                counters_sha256=compare.digest(args.counters), plugin_sha256=compare.digest(args.plugins / 'simpleudp.go.wasm'),
                runner_sha256=compare.digest(compare.__file__), diagnostic_sha256=compare.digest(__file__),
                controls=[{'flows': 64, 'pps': 400000}, {'flows': 4096, 'pps': 0}])
(output / 'environment.json').write_text(json.dumps(metadata, indent=2) + '\n')
(output / 'control.py').write_bytes(Path(__file__).read_bytes())
results = []
try:
    for index, (flows, pps) in enumerate(((64, 400000), (4096, 0))):
        settings = copy.copy(args)
        settings.flows, settings.pps = flows, pps
        case = dict(mode='vxlan', backend='xdp', frame_size=64, fanout=2, repeat=0,
                    workers=4, queues=4, cpu_redirect=True, forward_cpus=args.forward_cpus)
        directory = output / f'run-{index:03d}'
        directory.mkdir()
        trial = ProfileTrial(settings, case, directory)
        try:
            result = trial.run()
            (directory / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            results.append(result)
            (output / 'runs.json').write_text(json.dumps(results, indent=2) + '\n')
            print(flows, pps, result['offered_pps'], result['delivered_pps'], result['loss_fraction'], flush=True)
        finally:
            trial.close()
finally:
    if 'SUDO_UID' in os.environ:
        for path in [output, *output.rglob('*')]:
            os.chown(path, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))
