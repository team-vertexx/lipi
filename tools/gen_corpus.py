#!/usr/bin/env python3
"""
Write a corpus of perimeter-device log lines in eight vendor formats, laid out
the way each vendor documents them: Fortinet FortiGate key=value, Palo Alto
PAN-OS TRAFFIC CSV, Cisco ASA message IDs, Check Point CEF, pfSense filterlog,
Juniper SRX RT_FLOW structured syslog, Suricata EVE JSON and IBM LEEF 2.0.

The values are random (seeded, so the corpus is reproducible); the layouts are
the vendors'. This is a benchmark and test corpus, not captured traffic, and
every result measured on it says so.

    python3 tools/gen_corpus.py --lines 1000000 --out corpus.log
"""
import argparse
import calendar
import datetime as dt
import random


def private_ip(r):
    return f"10.{r.randint(0, 40)}.{r.randint(0, 255)}.{r.randint(1, 254)}"


def public_ip(r):
    first = r.choice([8, 13, 20, 23, 34, 52, 104, 142, 151, 157, 172, 185, 198, 203])
    return f"{first}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"


def epoch_ist(t):
    """Seconds since 1970 for a wall-clock time in India (UTC+05:30)."""
    return calendar.timegm(t.timetuple()) - 19800


MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


def fortigate(r, t):
    src, dst = private_ip(r), public_ip(r)
    sport, dport = r.randint(1024, 65535), r.choice([443, 80, 53, 22, 3389, 8080])
    proto = 17 if dport == 53 else 6
    action = r.choice(["accept", "close", "close", "deny", "timeout", "server-rst"])
    sb, rb = r.randint(40, 90000), r.randint(40, 900000)
    ev = epoch_ist(t) * 1000000000 + r.randint(0, 999999)
    return (f'<189>date={t:%Y-%m-%d} time={t:%H:%M:%S} devname="FGT-HQ-{r.randint(1, 4):02d}" '
            f'devid="FG100FTK1900{r.randint(1000, 9999)}" eventtime={ev} tz="+0530" '
            f'logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
            f'srcip={src} srcport={sport} srcintf="port1" srcintfrole="lan" dstip={dst} '
            f'dstport={dport} dstintf="wan1" dstintfrole="wan" srccountry="Reserved" '
            f'dstcountry="United States" sessionid={r.randint(1, 99999999)} proto={proto} '
            f'action="{action}" policyid={r.randint(1, 200)} policytype="policy" '
            f'service="{"DNS" if dport == 53 else "HTTPS"}" trandisp="snat" '
            f'transip=203.0.113.{r.randint(1, 254)} transport={sport} duration={r.randint(0, 600)} '
            f'sentbyte={sb} rcvdbyte={rb} sentpkt={r.randint(1, 900)} rcvdpkt={r.randint(1, 900)} '
            f'appcat="unscanned"')


def panos(r, t):
    src, dst = private_ip(r), public_ip(r)
    sport, dport = r.randint(1024, 65535), r.choice([443, 80, 53, 22, 25])
    proto = "udp" if dport == 53 else "tcp"
    action = r.choice(["allow", "allow", "allow", "deny", "drop", "reset-both"])
    sent, recv = r.randint(40, 90000), r.randint(40, 900000)
    ts = f"{t:%Y/%m/%d %H:%M:%S}"
    start = f"{t - dt.timedelta(seconds=30):%Y/%m/%d %H:%M:%S}"
    fields = ["1", ts, "013201001234", "TRAFFIC", "end", "2561", ts, src, dst,
              f"203.0.113.{r.randint(1, 254)}", dst, r.choice(["allow-web", "allow-dns", "block-bad"]),
              "", "", r.choice(["ssl", "dns", "web-browsing", "ssh"]), "vsys1", "trust", "untrust",
              "ethernet1/1", "ethernet1/2", "log-fwd", ts, str(r.randint(1, 9999999)), "1",
              str(sport), str(dport), str(r.randint(1024, 65535)), str(dport), "0x400019", proto,
              action, str(sent + recv), str(sent), str(recv), str(r.randint(2, 2000)), start,
              str(r.randint(0, 600)), "any", "0", str(r.randint(1, 10**12)), "0x0",
              "10.0.0.0-10.255.255.255", "United States", "0", str(r.randint(1, 900)),
              str(r.randint(1, 900)), r.choice(["aged-out", "tcp-fin", "tcp-rst-from-client", "policy-deny"])]
    return f"<14>{MONTHS[t.month - 1]} {t.day:2d} {t:%H:%M:%S} PA-5250 " + ",".join(fields)


def cisco_asa(r, t):
    head = f"<166>{MONTHS[t.month - 1]} {t.day:2d} {t:%Y %H:%M:%S} asa-edge-0{r.randint(1, 3)} : "
    src, dst = private_ip(r), public_ip(r)
    sport, dport = r.randint(1024, 65535), r.choice([443, 80, 22, 53])
    conn = r.randint(1, 99999999)
    k = r.random()
    if k < 0.35:
        return head + (f"%ASA-6-302013: Built outbound TCP connection {conn} for outside:{dst}/{dport} "
                       f"({dst}/{dport}) to inside:{src}/{sport} (203.0.113.10/{sport})")
    if k < 0.70:
        return head + (f"%ASA-6-302014: Teardown TCP connection {conn} for outside:{dst}/{dport} to "
                       f"inside:{src}/{sport} duration 0:00:{r.randint(0, 59):02d} bytes "
                       f"{r.randint(40, 900000)} TCP FINs")
    if k < 0.85:
        return head + (f"%ASA-6-302016: Teardown UDP connection {conn} for outside:{dst}/53 to "
                       f"inside:{src}/{sport} duration 0:00:00 bytes {r.randint(40, 1500)}")
    attacker = public_ip(r)
    return head + (f"%ASA-4-106023: Deny tcp src outside:{attacker}/{sport} dst inside:{src}/{dport} "
                   f'by access-group "OUTSIDE_IN" [0x0, 0x0]')


def checkpoint_cef(r, t):
    attacker, victim = public_ip(r), private_ip(r)
    dport = r.choice([22, 23, 445, 3389, 1433])
    act = r.choice(["Drop", "Reject", "Accept"])
    sev = r.choice(["Low", "Medium", "High"])
    msg = r.choice(["Connection dropped by rule", "Policy match\\= inbound block",
                    "Scan attempt from untrusted zone"])
    return (f"<134>{MONTHS[t.month - 1]} {t.day:2d} {t:%H:%M:%S} cp-gw-01 CEF:0|Check Point|"
            f"VPN-1 & FireWall-1|Check Point|{act}|{act}|{sev}|act={act} deviceDirection=0 "
            f"src={attacker} spt={r.randint(1024, 65535)} dst={victim} dpt={dport} proto=6 "
            f"cs2Label=Rule Name cs2=Block-Inbound-{dport} rt={epoch_ist(t) * 1000} "
            f"msg={msg}")


def pfsense(r, t):
    attacker, victim = public_ip(r), private_ip(r)
    dport = r.choice([22, 23, 445, 3389, 80])
    action = r.choice(["block", "block", "pass"])
    return (f"<134>{MONTHS[t.month - 1]} {t.day:2d} {t:%H:%M:%S} pfsense filterlog[40123]: "
            f"5,,,1000000103,igb0,match,{action},in,4,0x0,,64,{r.randint(1, 65535)},0,DF,6,tcp,60,"
            f"{attacker},{victim},{r.randint(1024, 65535)},{dport},0,S,{r.randint(1, 4294967295)},,"
            f"64240,,mss;sackOK;TS;nop;wscale")


def srx(r, t):
    src, dst = private_ip(r), public_ip(r)
    sport, dport = r.randint(1024, 65535), r.choice([443, 80, 53])
    proto = 17 if dport == 53 else 6
    ts = t.strftime("%Y-%m-%dT%H:%M:%S") + f".{r.randint(0, 999):03d}+05:30"
    return (f'<14>1 {ts} srx-branch-01 RT_FLOW - RT_FLOW_SESSION_CLOSE [junos@2636.1.1.1.2.129 '
            f'reason="TCP FIN" source-address="{src}" source-port="{sport}" '
            f'destination-address="{dst}" destination-port="{dport}" connection-tag="0" '
            f'service-name="junos-https" nat-source-address="203.0.113.10" nat-source-port="{sport}" '
            f'nat-destination-address="{dst}" nat-destination-port="{dport}" src-nat-rule-name="SNAT" '
            f'dst-nat-rule-name="N/A" protocol-id="{proto}" policy-name="TRUST-TO-UNTRUST" '
            f'source-zone-name="trust" destination-zone-name="untrust" session-id-32="{r.randint(1, 99999999)}" '
            f'packets-from-client="{r.randint(1, 900)}" bytes-from-client="{r.randint(40, 90000)}" '
            f'packets-from-server="{r.randint(1, 900)}" bytes-from-server="{r.randint(40, 900000)}" '
            f'elapsed-time="{r.randint(0, 600)}" application="SSL" nested-application="UNKNOWN" '
            f'username="N/A" roles="N/A" packet-incoming-interface="ge-0/0/1.0" encrypted="No"]')


def suricata(r, t):
    attacker, victim = public_ip(r), private_ip(r)
    sig = r.choice([(2001219, "ET SCAN Potential SSH Scan", "Attempted Information Leak", 2),
                    (2010935, "ET SCAN Suspicious inbound to MSSQL port 1433", "Potentially Bad Traffic", 2),
                    (2024897, "ET USER_AGENTS Go HTTP Client User-Agent", "Misc activity", 3)])
    ts = t.strftime("%Y-%m-%dT%H:%M:%S") + f".{r.randint(0, 999999):06d}+0530"
    return (f'{{"timestamp":"{ts}","flow_id":{r.randint(1, 2**52)},"in_iface":"eth1",'
            f'"event_type":"alert","src_ip":"{attacker}","src_port":{r.randint(1024, 65535)},'
            f'"dest_ip":"{victim}","dest_port":{r.choice([22, 80, 1433, 443])},"proto":"TCP",'
            f'"alert":{{"action":"allowed","gid":1,"signature_id":{sig[0]},"rev":20,'
            f'"signature":"{sig[1]}","category":"{sig[2]}","severity":{sig[3]}}}}}')


def leef(r, t):
    src, dst = private_ip(r), public_ip(r)
    return (f"LEEF:2.0|Sophos|XG Firewall|19.5|firewall-traffic|^|devTime={epoch_ist(t) * 1000}"
            f"^src={src}^dst={dst}^srcPort={r.randint(1024, 65535)}^dstPort={r.choice([443, 80, 53])}"
            f"^proto=6^action={r.choice(['allow', 'deny'])}^srcBytes={r.randint(40, 90000)}"
            f"^dstBytes={r.randint(40, 900000)}^usrName=N/A^policy=LAN_to_WAN")


FORMATS = [(fortigate, 22), (panos, 18), (cisco_asa, 18), (checkpoint_cef, 10), (pfsense, 10),
           (srx, 10), (suricata, 7), (leef, 5)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lines", type=int, default=1000000)
    ap.add_argument("--seed", type=int, default=26156)
    ap.add_argument("--out", default="corpus.log")
    args = ap.parse_args()
    r = random.Random(args.seed)
    gens = [g for g, w in FORMATS for _ in range(w)]
    t = dt.datetime(2026, 9, 28, 9, 0, 0)
    with open(args.out, "w") as fh:
        for i in range(args.lines):
            if i % 50 == 0:
                t += dt.timedelta(seconds=1)
            fh.write(r.choice(gens)(r, t))
            fh.write("\n")


if __name__ == "__main__":
    main()
