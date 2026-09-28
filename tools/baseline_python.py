#!/usr/bin/env python3
"""
The comparison point: the same eight formats normalised the way most Python
log pipelines do it (regular expressions, str.split, json.loads, a dict per
event, json.dumps), on the same corpus and the same machine as lipi bench.

    python3 tools/baseline_python.py corpus.log --lines 200000
"""
import argparse
import json
import re
import time

KV = re.compile(r'(\w[\w-]*)=("(?:[^"\\]|\\.)*"|\S+)')
CEF_KV = re.compile(r'(\w+)=((?:\\=|[^=])*?)(?=\s\w+=|$)')
ASA = re.compile(r'%ASA-(\d)-(\d+): (.*)')
EP = re.compile(r'(\w+):([\d.]+)/(\d+)')
HDR3164 = re.compile(r'^(?:<\d+>)?(\w{3} +\d+ (?:\d{4} )?\d\d:\d\d:\d\d) (\S+) (.*)$')


def kv(s):
    return {k: v.strip('"') for k, v in KV.findall(s)}


def normalise(line):
    ev = {"class_uid": 4001, "raw_data": line}
    body = line
    if line.startswith("<"):
        body = line[line.index(">") + 1:]
    if body.startswith("date="):
        d = kv(body)
        ev.update(src_endpoint={"ip": d.get("srcip"), "port": int(d.get("srcport", 0))},
                  dst_endpoint={"ip": d.get("dstip"), "port": int(d.get("dstport", 0))},
                  traffic={"bytes_out": int(d.get("sentbyte", 0)), "bytes_in": int(d.get("rcvdbyte", 0))},
                  unmapped=d)
        return ev
    if body.startswith("1 "):  # RFC 5424, Juniper SRX
        sd = body[body.index("[") + 1:body.rindex("]")]
        d = kv(sd)
        ev.update(src_endpoint={"ip": d.get("source-address"), "port": int(d.get("source-port", 0))},
                  dst_endpoint={"ip": d.get("destination-address"), "port": int(d.get("destination-port", 0))},
                  unmapped=d)
        return ev
    if body.startswith("{"):
        d = json.loads(body)
        ev.update(src_endpoint={"ip": d.get("src_ip"), "port": d.get("src_port")},
                  dst_endpoint={"ip": d.get("dest_ip"), "port": d.get("dest_port")}, unmapped=d)
        return ev
    if body.startswith("LEEF:"):
        parts = body.split("|", 6)
        d = dict(p.split("=", 1) for p in parts[6].split(parts[5]) if "=" in p)
        ev.update(src_endpoint={"ip": d.get("src")}, dst_endpoint={"ip": d.get("dst")}, unmapped=d)
        return ev
    m = HDR3164.match(body)
    msg = m.group(3) if m else body
    if "CEF:" in msg:
        cef = msg[msg.index("CEF:"):]
        parts = cef.split("|", 7)
        d = dict(CEF_KV.findall(parts[7]))
        ev.update(src_endpoint={"ip": d.get("src")}, dst_endpoint={"ip": d.get("dst")}, unmapped=d)
        return ev
    a = ASA.search(msg)
    if a:
        eps = EP.findall(a.group(3))
        if len(eps) >= 2:
            ev.update(src_endpoint={"ip": eps[1][1], "port": int(eps[1][2])},
                      dst_endpoint={"ip": eps[0][1], "port": int(eps[0][2])})
        ev["message"] = a.group(3)
        return ev
    if msg.startswith("filterlog"):
        f = msg.split(": ", 1)[1].split(",")
        ev.update(src_endpoint={"ip": f[18], "port": int(f[20])}, dst_endpoint={"ip": f[19], "port": int(f[21])})
        return ev
    f = msg.split(",")
    if len(f) > 33 and f[3] == "TRAFFIC":
        ev.update(src_endpoint={"ip": f[7], "port": int(f[24])}, dst_endpoint={"ip": f[8], "port": int(f[25])},
                  traffic={"bytes_out": int(f[32]), "bytes_in": int(f[33])})
        return ev
    ev["class_uid"] = 0
    return ev


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--lines", type=int, default=200000)
    args = ap.parse_args()
    lines = []
    with open(args.path) as fh:
        for i, line in enumerate(fh):
            if i >= args.lines:
                break
            lines.append(line.rstrip("\n"))
    t0 = time.perf_counter()
    out = 0
    for line in lines:
        out += len(json.dumps(normalise(line)))
    s = time.perf_counter() - t0
    print(f"lines {len(lines)}  seconds {s:.2f}  events/s {len(lines) / s:.0f}  output MB {out / 1e6:.1f}")


if __name__ == "__main__":
    main()
