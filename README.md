# Lipi

**लिपि (lipi)** is Hindi and Sanskrit for *script*: one way of writing that
many languages share. Lipi does that for perimeter logs. Firewalls, IPS and
gateways from different vendors each write in their own dialect, and Lipi turns
every line into one standard event (OCSF) without losing a byte of the
original.

Built for SIH 2026, problem statement **SIH26156** (NTRO: Universal Log
Pre-processing Framework). C++20, standard library only, no runtime
dependencies, so it runs in an air-gapped network as a single binary.

## What the prototype does today

- Reads eight perimeter formats: Fortinet FortiGate (key=value), Palo Alto
  PAN-OS TRAFFIC (positional CSV), Cisco ASA (per message ID), Check Point CEF,
  pfSense filterlog, Juniper SRX RT_FLOW (RFC 5424 structured data), Suricata
  EVE JSON and IBM LEEF 2.0, behind RFC 3164 and RFC 5424 syslog headers.
- Normalises each to OCSF 1.3 (Network Activity 4001, Detection Finding 2004),
  every timestamp to UTC with the device's offset kept, and keeps every field it
  does not map in `unmapped`, the original line in `raw_data`, and a hash of it.
- Copies nothing while parsing: every field is a view into its own raw line,
  so each value can name the exact bytes it came from. `lipi verify` checks
  that for every field of every line rather than assuming it.

## Measured

On a 2-core Intel Xeon at 2.1 GHz (cloud VM), one million lines, 411 MB, all
eight formats mixed (`tools/gen_corpus.py`, seeded, vendor-documented layouts
with random values; a benchmark corpus, not captured traffic):

| | result |
|---|---|
| parse + normalise, 1 core | **1,505,807 events/s** |
| parse + normalise + OCSF JSON, 1 core | **486,097 events/s** |
| parse + normalise + OCSF JSON, 2 cores | **1,000,274 events/s** |
| per-event latency, 1 core (p50 / p99 / p99.9) | **1.97 / 5.72 / 25.4 µs** |
| lines fully parsed | **100%** (1,000,000 of 1,000,000) |
| field values checked to be views into their raw line | 22,052,126, **0 outside** |
| same corpus, Python regex + json pipeline, 1 core | 48,416 events/s |
| file in, OCSF out (to /dev/null), 2 cores | 2.0 s per million events |

Writing the 1.52 GB of OCSF JSON to this VM's disk takes longer than producing
it: the engine is not the bottleneck, storage is.

```bash
cmake -S . -B build -G Ninja && cmake --build build
python3 tools/gen_corpus.py --lines 1000000 --out corpus.log
build/lipi verify corpus.log
build/lipi bench corpus.log --threads=1 --parse-only
build/lipi bench corpus.log --threads=2
build/lipi latency corpus.log
build/lipi normalize corpus.log --out=corpus.ocsf.json
python3 tools/baseline_python.py corpus.log --lines 200000
```

Raw outputs are in `bench/results/`.

## Not built yet

Template mining for unknown sources, the compressed searchable raw vault, the
tamper-evident chain, network ingest and the operator console are the design,
not the prototype. The idea deck marks each as planned.

## Team

Team_Vertex_, Indian Institute of Technology Kharagpur.
