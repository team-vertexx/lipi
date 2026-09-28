// Format recognition and the eight vendor parsers.
//
// Every parser walks the line once, left to right, and stores views into it.
// Nothing is allocated and nothing is copied, which is what lets one core keep
// up with a firewall farm: the cost per line is a handful of passes over a few
// hundred bytes that are already in cache.
#include <cstring>

#include "lipi.hpp"

namespace lipi {

const char* fmt_name(Fmt f) {
  switch (f) {
    case Fmt::kFortiGate: return "fortigate";
    case Fmt::kPanTraffic: return "panos_traffic";
    case Fmt::kCiscoAsa: return "cisco_asa";
    case Fmt::kCef: return "cef";
    case Fmt::kPfFilterlog: return "pfsense_filterlog";
    case Fmt::kSrxFlow: return "juniper_srx";
    case Fmt::kSuricataEve: return "suricata_eve";
    case Fmt::kLeef: return "leef";
    default: return "unknown";
  }
}

namespace {

inline bool starts(sv s, sv p) { return s.size() >= p.size() && std::memcmp(s.data(), p.data(), p.size()) == 0; }

inline bool to_u64(sv s, std::uint64_t& v) {
  if (s.empty() || s.size() > 20) return false;
  std::uint64_t r = 0;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
    r = r * 10 + static_cast<std::uint64_t>(c - '0');
  }
  v = r;
  return true;
}

inline bool to_port(sv s, std::uint32_t& p) {
  std::uint64_t v = 0;
  if (!to_u64(s, v) || v > 65535) return false;
  p = static_cast<std::uint32_t>(v);
  return true;
}

inline int proto_from_name(sv s) {
  if (s == "tcp" || s == "TCP" || s == "6") return 6;
  if (s == "udp" || s == "UDP" || s == "17") return 17;
  if (s == "icmp" || s == "ICMP" || s == "1") return 1;
  std::uint64_t v = 0;
  return to_u64(s, v) && v < 256 ? static_cast<int>(v) : -1;
}

// Days since 1970-01-01 for a civil date (H. Hinnant's algorithm).
inline std::int64_t days_from_civil(std::int64_t y, unsigned m, unsigned d) {
  y -= m <= 2;
  const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

inline int d2(const char* p) { return (p[0] - '0') * 10 + (p[1] - '0'); }
inline int d4(const char* p) { return d2(p) * 100 + d2(p + 2); }

inline std::int64_t epoch_ms(int y, int mo, int d, int h, int mi, int s, int ms, int tz_min) {
  const std::int64_t days = days_from_civil(y, static_cast<unsigned>(mo), static_cast<unsigned>(d));
  return (((days * 24 + h) * 60 + mi) * 60 + s) * 1000 + ms - static_cast<std::int64_t>(tz_min) * 60000;
}

inline int month_of(const char* p) {
  static const char* kM = "JanFebMarAprMayJunJulAugSepOctNovDec";
  for (int i = 0; i < 12; ++i)
    if (std::memcmp(kM + 3 * i, p, 3) == 0) return i + 1;
  return 0;
}

// "2026-09-28T10:22:01.123+05:30" or "...123456+0530" (ISO 8601 with offset).
bool iso_time(sv s, Event& e) {
  if (s.size() < 19 || s[4] != '-' || s[10] != 'T') return false;
  const char* p = s.data();
  int ms = 0;
  std::size_t i = 19;
  if (i < s.size() && s[i] == '.') {
    int digits = 0;
    ++i;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
      if (digits < 3) ms = ms * 10 + (s[i] - '0');
      ++digits;
      ++i;
    }
    while (digits > 0 && digits < 3) { ms *= 10; ++digits; }
  }
  int tz = 0;
  if (i < s.size() && (s[i] == '+' || s[i] == '-')) {
    const int sign = s[i] == '-' ? -1 : 1;
    const int hh = d2(p + i + 1);
    const int mm = (i + 3 < s.size() && s[i + 3] == ':') ? d2(p + i + 4) : d2(p + i + 3);
    tz = sign * (hh * 60 + mm);
  }
  e.tz_min = tz;
  e.time_ms = epoch_ms(d4(p), d2(p + 5), d2(p + 8), d2(p + 11), d2(p + 14), d2(p + 17), ms, tz);
  e.has_time = true;
  e.time_text = s;
  return true;
}

// "2026/09/28 10:22:01" or "2026-09-28 10:22:01", device local time.
bool ymd_hms(sv s, Event& e) {
  if (s.size() < 19) return false;
  const char* p = s.data();
  e.time_ms = epoch_ms(d4(p), d2(p + 5), d2(p + 8), d2(p + 11), d2(p + 14), d2(p + 17), 0, e.tz_min);
  e.has_time = true;
  e.time_text = s.substr(0, 19);
  return true;
}

// ---------------------------------------------------------------- syslog header
// RFC 3164 has no year and no zone; the year is taken from the collector's
// configuration (here fixed to the corpus year) and the zone from the device's
// configured offset. That is the rule every SIEM applies, and it is stated here
// rather than hidden.
constexpr int kAssumedYear = 2026;

struct Header {
  sv msg;       // what follows the header
  sv msgid;     // RFC 5424 MSGID
  sv sd;        // RFC 5424 structured data, brackets included
};

bool syslog_header(sv line, Event& e, Header& h) {
  sv s = line;
  if (!s.empty() && s[0] == '<') {
    std::size_t gt = s.find('>');
    if (gt == sv::npos || gt > 4) return false;
    s.remove_prefix(gt + 1);
  }
  // RFC 5424: "1 2026-09-28T10:22:01.123+05:30 host app procid msgid [sd] msg"
  if (s.size() > 2 && s[0] == '1' && s[1] == ' ') {
    s.remove_prefix(2);
    sv f[5];
    for (int k = 0; k < 5; ++k) {
      std::size_t sp = s.find(' ');
      if (sp == sv::npos) return false;
      f[k] = s.substr(0, sp);
      s.remove_prefix(sp + 1);
    }
    iso_time(f[0], e);
    e.host = f[1];
    e.app = f[2];
    h.msgid = f[4];
    if (!s.empty() && s[0] == '[') {
      // structured data: find the closing bracket that is not escaped
      std::size_t i = 1;
      bool in_quote = false;
      for (; i < s.size(); ++i) {
        const char c = s[i];
        if (c == '\\') { ++i; continue; }
        if (c == '"') in_quote = !in_quote;
        else if (c == ']' && !in_quote) break;
      }
      h.sd = s.substr(0, i + 1 <= s.size() ? i + 1 : s.size());
      s.remove_prefix(h.sd.size());
      if (!s.empty() && s[0] == ' ') s.remove_prefix(1);
    } else if (!s.empty() && s[0] == '-') {
      s.remove_prefix(s.size() > 1 ? 2 : 1);
    }
    h.msg = s;
    return true;
  }
  // RFC 3164: "Sep 28 10:22:01 host tag: msg", ASA adds a year after the day.
  if (s.size() > 16 && s[3] == ' ' && month_of(s.data())) {
    const char* p = s.data();
    const int mo = month_of(p);
    const int day = (p[4] == ' ' ? 0 : (p[4] - '0') * 10) + (p[5] - '0');
    std::size_t i = 7;
    int year = kAssumedYear;
    if (s.size() > 12 && s[11] == ' ' && s[9] != ':') {  // "Sep 28 2026 10:22:01"
      year = d4(p + 7);
      i = 12;
    }
    if (i + 8 > s.size() || p[i + 2] != ':') return false;
    e.time_ms = epoch_ms(year, mo, day, d2(p + i), d2(p + i + 3), d2(p + i + 6), 0, e.tz_min);
    e.has_time = true;
    e.time_text = s.substr(0, i + 8);
    s.remove_prefix(i + 8);
    if (!s.empty() && s[0] == ' ') s.remove_prefix(1);
    std::size_t sp = s.find(' ');
    if (sp == sv::npos) return false;
    e.host = s.substr(0, sp);
    s.remove_prefix(sp + 1);
    h.msg = s;
    return true;
  }
  h.msg = s;  // no header (FortiGate after the PRI, bare JSON, bare LEEF)
  return true;
}

// ---------------------------------------------------------------- key=value
// FortiGate and SRX style: key=value or key="value", separated by spaces.
// SRX quotes may contain \" and \\ (RFC 5424 escaping).
template <typename F>
bool scan_kv(sv s, F&& on_pair, sv& rest) {
  std::size_t i = 0;
  const std::size_t n = s.size();
  while (i < n) {
    while (i < n && s[i] == ' ') ++i;
    if (i >= n) break;
    const std::size_t k0 = i;
    while (i < n && s[i] != '=' && s[i] != ' ') ++i;
    if (i >= n || s[i] != '=') { rest = s.substr(k0); return false; }
    const sv key = s.substr(k0, i - k0);
    ++i;
    sv val;
    if (i < n && s[i] == '"') {
      const std::size_t v0 = ++i;
      while (i < n && s[i] != '"') {
        if (s[i] == '\\') ++i;
        ++i;
      }
      if (i >= n) { rest = s.substr(k0); return false; }
      val = s.substr(v0, i - v0);
      ++i;
    } else {
      const std::size_t v0 = i;
      while (i < n && s[i] != ' ') ++i;
      val = s.substr(v0, i - v0);
    }
    on_pair(key, val);
  }
  return true;
}

// ---------------------------------------------------------------- CSV
// Fields separated by commas; a field may be quoted and contain commas.
inline int split_csv(sv s, sv* out, int max) {
  int n = 0;
  std::size_t i = 0;
  while (n < max) {
    if (i < s.size() && s[i] == '"') {
      const std::size_t v0 = ++i;
      while (i < s.size() && s[i] != '"') ++i;
      out[n++] = s.substr(v0, i - v0);
      if (i < s.size()) ++i;
    } else {
      const std::size_t v0 = i;
      while (i < s.size() && s[i] != ',') ++i;
      out[n++] = s.substr(v0, i - v0);
    }
    if (i >= s.size()) break;
    ++i;  // the comma
  }
  return n;
}

// ---------------------------------------------------------------- FortiGate
bool parse_fortigate(sv s, Event& e) {
  e.fmt = Fmt::kFortiGate;
  e.vendor = "Fortinet";
  e.product = "FortiGate";
  e.class_uid = 4001;
  sv date, time, action, eventtime;
  sv rest;
  const bool ok = scan_kv(s, [&](sv k, sv v) {
    switch (k.size()) {
      case 2: if (k == "tz") { if (v.size() == 5) e.tz_min = (v[0] == '-' ? -1 : 1) * (d2(v.data() + 1) * 60 + d2(v.data() + 3)); return; } break;
      case 4:
        if (k == "date") { date = v; return; }
        if (k == "time") { time = v; return; }
        if (k == "type") { e.log_name = v; return; }
        break;
      case 5:
        if (k == "srcip") { e.src_ip = v; return; }
        if (k == "dstip") { e.dst_ip = v; return; }
        if (k == "proto") { e.proto = proto_from_name(v); return; }
        if (k == "level") { e.severity_id = v == "notice" || v == "information" ? 1 : v == "warning" ? 3 : v == "error" ? 4 : v == "critical" || v == "alert" || v == "emergency" ? 5 : 2; return; }
        break;
      case 6:
        if (k == "action") { action = v; return; }
        break;
      case 7:
        if (k == "srcport") { e.has_sport = to_port(v, e.src_port); return; }
        if (k == "dstport") { e.has_dport = to_port(v, e.dst_port); return; }
        if (k == "devname") { e.host = v; return; }
        if (k == "service") { e.app_name = v; return; }
        if (k == "sentpkt") { std::uint64_t x; if (to_u64(v, x)) { e.pkts_out = x; e.has_pkts = true; } return; }
        if (k == "rcvdpkt") { std::uint64_t x; if (to_u64(v, x)) { e.pkts_in = x; e.has_pkts = true; } return; }
        break;
      case 8:
        if (k == "sentbyte") { std::uint64_t x; if (to_u64(v, x)) { e.bytes_out = x; e.has_bytes = true; } return; }
        if (k == "rcvdbyte") { std::uint64_t x; if (to_u64(v, x)) { e.bytes_in = x; e.has_bytes = true; } return; }
        if (k == "policyid") { e.rule = v; return; }
        break;
      case 9:
        if (k == "eventtime") { eventtime = v; return; }
        break;
      default: break;
    }
    e.keep(k, v);
  }, rest);
  if (!ok) { e.complete = false; e.rest = rest; e.keep("_unparsed", rest); }
  std::uint64_t ns = 0;
  if (to_u64(eventtime, ns)) {
    e.time_ms = static_cast<std::int64_t>(ns / 1000000);
    e.has_time = true;
    e.time_text = eventtime;
  } else if (date.size() == 10 && time.size() == 8) {
    const char* p = date.data();
    const char* q = time.data();
    e.time_ms = epoch_ms(d4(p), d2(p + 5), d2(p + 8), d2(q), d2(q + 3), d2(q + 6), 0, e.tz_min);
    e.has_time = true;
    e.time_text = date;
  }
  if (action == "accept" || action == "close" || action == "timeout" || action == "server-rst" || action == "client-rst") {
    e.action_id = 1;
    e.activity_id = action == "accept" ? 1 : action == "close" ? 2 : action == "timeout" ? 4 : 3;
  } else if (action == "deny") {
    e.action_id = 2;
    e.activity_id = 5;
  } else {
    e.activity_id = 6;
  }
  if (!action.empty()) e.keep("action", action);
  return true;
}

// ---------------------------------------------------------------- PAN-OS TRAFFIC
// Positional CSV, PAN-OS 10 layout. Index names follow the vendor's field list.
bool parse_pan_traffic(sv s, Event& e) {
  sv f[64];
  const int n = split_csv(s, f, 64);
  if (n < 47 || f[3] != "TRAFFIC") return false;
  e.fmt = Fmt::kPanTraffic;
  e.vendor = "Palo Alto Networks";
  e.product = "PAN-OS";
  e.class_uid = 4001;
  e.log_name = f[3];
  ymd_hms(f[6], e);
  e.src_ip = f[7];
  e.dst_ip = f[8];
  e.rule = f[11];
  e.app_name = f[14];
  e.has_sport = to_port(f[24], e.src_port);
  e.has_dport = to_port(f[25], e.dst_port);
  e.proto = proto_from_name(f[29]);
  const sv action = f[30];
  e.action_id = action == "allow" ? 1 : (action == "deny" || action == "drop" || starts(action, "reset")) ? 2 : 0;
  e.activity_id = f[4] == "start" ? 1 : f[4] == "end" ? 2 : e.action_id == 2 ? 5 : 6;
  std::uint64_t x = 0;
  if (to_u64(f[32], x)) { e.bytes_out = x; e.has_bytes = true; }
  if (to_u64(f[33], x)) { e.bytes_in = x; e.has_bytes = true; }
  if (to_u64(f[44], x)) { e.pkts_out = x; e.has_pkts = true; }
  if (to_u64(f[45], x)) { e.pkts_in = x; e.has_pkts = true; }
  e.reason = f[46];
  // everything positional that was not mapped keeps its vendor name
  static const char* kNames[] = {"future_use_0", "receive_time", "serial", "type", "subtype", "config_version",
                                 "generated_time", "src", "dst", "natsrc", "natdst", "rule", "srcuser", "dstuser",
                                 "app", "vsys", "from_zone", "to_zone", "inbound_if", "outbound_if", "logset",
                                 "time_logged", "sessionid", "repeatcnt", "sport", "dport", "natsport", "natdport",
                                 "flags", "proto", "action", "bytes", "bytes_sent", "bytes_received", "packets",
                                 "start", "elapsed", "category", "future_use_38", "seqno", "actionflags",
                                 "srcloc", "dstloc", "future_use_43", "pkts_sent", "pkts_received", "session_end_reason"};
  for (int i = 0; i < n; ++i) {
    if (i == 6 || i == 7 || i == 8 || i == 11 || i == 14 || i == 24 || i == 25 || i == 29 || i == 32 || i == 33 || i == 44 || i == 45 || i == 46) continue;
    if (f[i].empty()) continue;
    e.keep(i < 47 ? sv(kNames[i]) : sv("extra"), f[i]);
  }
  e.keep("action", action);
  return true;
}

// ---------------------------------------------------------------- Cisco ASA
// "%ASA-6-302013: Built outbound TCP connection ..." One template per message
// ID; an unknown ID keeps its text as the message, so it is never lost.
inline bool endpoint(sv tok, sv& ifc, sv& ip, std::uint32_t& port) {
  // "outside:8.8.8.8/443"
  const std::size_t c = tok.find(':');
  const std::size_t sl = tok.rfind('/');
  if (c == sv::npos || sl == sv::npos || sl < c) return false;
  ifc = tok.substr(0, c);
  ip = tok.substr(c + 1, sl - c - 1);
  return to_port(tok.substr(sl + 1), port);
}

bool parse_asa(sv s, Event& e) {
  // s starts at "%ASA-"
  if (s.size() < 14 || s[6] != '-' || s[13] != ':') return false;
  e.fmt = Fmt::kCiscoAsa;
  e.vendor = "Cisco";
  e.product = "ASA";
  const int sev = s[5] - '0';
  e.severity_id = sev <= 2 ? 5 : sev == 3 ? 4 : sev == 4 ? 3 : sev == 5 ? 2 : 1;
  const sv id = s.substr(7, 6);
  e.sig_uid = id;
  sv msg = s.substr(14);
  if (!msg.empty() && msg[0] == ' ') msg.remove_prefix(1);
  e.message = msg;
  e.class_uid = 4001;
  // tokenise on spaces into a small array; ASA messages are short
  sv t[32];
  int n = 0;
  {
    std::size_t i = 0;
    while (i < msg.size() && n < 32) {
      while (i < msg.size() && msg[i] == ' ') ++i;
      const std::size_t a = i;
      while (i < msg.size() && msg[i] != ' ') ++i;
      if (i > a) t[n++] = msg.substr(a, i - a);
    }
  }
  sv ifc_a, ifc_b;
  if ((id == "302013" || id == "302015") && n >= 10 && t[0] == "Built") {
    // Built {inbound|outbound} {TCP|UDP} connection ID for A (mapped) to B (mapped)
    e.proto = proto_from_name(t[2]);
    sv ip_a, ip_b;
    std::uint32_t pa = 0, pb = 0;
    if (!endpoint(t[6], ifc_a, ip_a, pa) || !endpoint(t[9], ifc_b, ip_b, pb)) return false;
    const bool outbound = t[1] == "outbound";
    e.src_ip = outbound ? ip_b : ip_a;
    e.src_port = outbound ? pb : pa;
    e.dst_ip = outbound ? ip_a : ip_b;
    e.dst_port = outbound ? pa : pb;
    e.has_sport = e.has_dport = true;
    e.activity_id = 1;
    e.action_id = 1;
    e.keep("connection_id", t[4]);
    e.keep("direction", t[1]);
    e.keep("src_interface", outbound ? ifc_b : ifc_a);
    e.keep("dst_interface", outbound ? ifc_a : ifc_b);
    e.keep("mapped_a", t[7]);
    e.keep("mapped_b", t[10 < n ? 10 : n - 1]);
    return true;
  }
  if ((id == "302014" || id == "302016") && n >= 10 && t[0] == "Teardown") {
    // Teardown {TCP|UDP} connection ID for A to B duration H:MM:SS bytes N [reason]
    e.proto = proto_from_name(t[1]);
    sv ip_a, ip_b;
    std::uint32_t pa = 0, pb = 0;
    if (!endpoint(t[5], ifc_a, ip_a, pa) || !endpoint(t[7], ifc_b, ip_b, pb)) return false;
    e.src_ip = ip_b;
    e.src_port = pb;
    e.dst_ip = ip_a;
    e.dst_port = pa;
    e.has_sport = e.has_dport = true;
    e.activity_id = 2;
    e.action_id = 1;
    std::uint64_t b = 0;
    if (n > 11 && t[10] == "bytes" && to_u64(t[11], b)) { e.bytes_in = b; e.has_bytes = true; }
    e.keep("connection_id", t[3]);
    e.keep("duration", t[9]);
    e.keep("src_interface", ifc_b);
    e.keep("dst_interface", ifc_a);
    if (n > 12) {
      const std::size_t off = static_cast<std::size_t>(t[12].data() - msg.data());
      e.reason = msg.substr(off);
    }
    return true;
  }
  if (id == "106023" && n >= 8 && t[0] == "Deny") {
    // Deny PROTO src A dst B by access-group "ACL" [0x0, 0x0]
    e.proto = proto_from_name(t[1]);
    std::uint32_t pa = 0, pb = 0;
    if (!endpoint(t[3], ifc_a, e.src_ip, pa) || !endpoint(t[5], ifc_b, e.dst_ip, pb)) return false;
    e.src_port = pa;
    e.dst_port = pb;
    e.has_sport = e.has_dport = true;
    e.activity_id = 5;
    e.action_id = 2;
    if (n > 8) {
      sv acl = t[8];
      if (acl.size() >= 2 && acl.front() == '"') acl = acl.substr(1, acl.size() - 2);
      e.rule = acl;
    }
    e.keep("src_interface", ifc_a);
    e.keep("dst_interface", ifc_b);
    if (n > 9) {
      const std::size_t off = static_cast<std::size_t>(t[9].data() - msg.data());
      e.keep("hash_values", msg.substr(off));
    }
    return true;
  }
  // an ID without a template: a Base Event that still carries the whole message
  e.class_uid = 0;
  e.activity_id = 99;
  return true;
}

// ---------------------------------------------------------------- CEF
// CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension
// Header fields escape | and \ ; extension values escape = and \ and may hold
// spaces, so a value ends where the next "key=" begins.
bool parse_cef(sv s, Event& e) {
  sv h[8];
  int n = 0;
  std::size_t i = 0, a = 0;
  for (; i < s.size() && n < 7; ++i) {
    if (s[i] == '\\') { ++i; continue; }
    if (s[i] == '|') { h[n++] = s.substr(a, i - a); a = i + 1; }
  }
  if (n < 7) return false;
  e.fmt = Fmt::kCef;
  e.vendor = h[1];
  e.product = h[2];
  e.sig_uid = h[4];
  e.signature = h[5];
  const sv sev = h[6];
  e.severity_id = sev == "Low" ? 2 : sev == "Medium" ? 3 : sev == "High" ? 4 : sev == "Very-High" ? 5 : 1;
  e.class_uid = 4001;
  sv ext = s.substr(a);
  // collect unescaped '=' positions
  std::size_t eq[128];
  int m = 0;
  for (std::size_t k = 0; k < ext.size() && m < 128; ++k) {
    if (ext[k] == '\\') { ++k; continue; }
    if (ext[k] == '=') eq[m++] = k;
  }
  sv cs_label[8];
  sv cs_value[8];
  for (int k = 0; k < m; ++k) {
    std::size_t ks = eq[k];
    while (ks > 0 && ext[ks - 1] != ' ') --ks;
    const sv key = ext.substr(ks, eq[k] - ks);
    std::size_t ve = ext.size();
    if (k + 1 < m) {
      ve = eq[k + 1];
      while (ve > 0 && ext[ve - 1] != ' ') --ve;
      if (ve > 0) --ve;  // the space before the next key
    }
    const sv val = ext.substr(eq[k] + 1, ve > eq[k] + 1 ? ve - eq[k] - 1 : 0);
    if (key == "src") e.src_ip = val;
    else if (key == "dst") e.dst_ip = val;
    else if (key == "spt") e.has_sport = to_port(val, e.src_port);
    else if (key == "dpt") e.has_dport = to_port(val, e.dst_port);
    else if (key == "proto") e.proto = proto_from_name(val);
    else if (key == "act") {
      e.action_id = (val == "Accept" || val == "allow" || val == "Allow") ? 1 : 2;
      e.activity_id = e.action_id == 2 ? 5 : 6;
      e.keep(key, val);
    } else if (key == "rt") {
      std::uint64_t ms = 0;
      if (to_u64(val, ms)) { e.time_ms = static_cast<std::int64_t>(ms); e.has_time = true; e.time_text = val; }
    } else if (key == "msg") e.message = val;
    else if (key.size() == 8 && starts(key, "cs") && key.substr(3) == "Label") cs_label[(key[2] - '0') & 7] = val;
    else if (key.size() == 3 && starts(key, "cs") && key[2] >= '1' && key[2] <= '6') cs_value[(key[2] - '0') & 7] = val;
    else e.keep(key, val);
  }
  for (int k = 1; k <= 6; ++k) {
    if (cs_value[k].empty()) continue;
    if (cs_label[k] == "Rule Name") e.rule = cs_value[k];
    else e.keep(cs_label[k].empty() ? sv("cs") : cs_label[k], cs_value[k]);
  }
  return true;
}

// ---------------------------------------------------------------- pfSense filterlog
// rule,subrule,anchor,tracker,iface,reason,action,dir,ipver,[ipv4: tos,ecn,ttl,
// id,offset,flags,protoid,proto,length,src,dst],[tcp/udp: sport,dport,datalen,
// tcp: flags,seq,ack,window,urg,options]
bool parse_filterlog(sv s, Event& e) {
  sv f[40];
  const int n = split_csv(s, f, 40);
  if (n < 20 || f[8] != "4") return false;
  e.fmt = Fmt::kPfFilterlog;
  e.vendor = "Netgate";
  e.product = "pfSense";
  e.class_uid = 4001;
  e.rule = f[3];
  const sv action = f[6];
  e.action_id = action == "pass" ? 1 : 2;
  e.activity_id = e.action_id == 2 ? 5 : 6;
  e.proto = proto_from_name(f[15]);
  e.src_ip = f[18];
  e.dst_ip = f[19];
  if (n > 21) {
    e.has_sport = to_port(f[20], e.src_port);
    e.has_dport = to_port(f[21], e.dst_port);
  }
  static const char* kNames[] = {"rule", "subrule", "anchor", "tracker", "interface", "reason", "action", "direction",
                                 "ip_version", "tos", "ecn", "ttl", "id", "offset", "ip_flags", "proto_id", "proto",
                                 "length", "src", "dst", "sport", "dport", "data_length", "tcp_flags", "seq", "ack",
                                 "window", "urg", "options"};
  for (int i = 0; i < n; ++i) {
    if (i == 3 || i == 15 || i == 18 || i == 19 || (n > 21 && (i == 20 || i == 21))) continue;
    if (f[i].empty()) continue;
    e.keep(i < 29 ? sv(kNames[i]) : sv("extra"), f[i]);
  }
  return true;
}

// ---------------------------------------------------------------- Juniper SRX
bool parse_srx(sv sd, sv msgid, Event& e) {
  e.fmt = Fmt::kSrxFlow;
  e.vendor = "Juniper Networks";
  e.product = "SRX";
  e.class_uid = 4001;
  e.log_name = msgid;
  e.activity_id = msgid == "RT_FLOW_SESSION_CREATE" ? 1 : msgid == "RT_FLOW_SESSION_CLOSE" ? 2 : msgid == "RT_FLOW_SESSION_DENY" ? 5 : 6;
  e.action_id = e.activity_id == 5 ? 2 : 1;
  // "[junos@2636.1.1.1.2.129 k="v" ...]"
  if (sd.size() < 2 || sd.front() != '[' || sd.back() != ']') return false;
  sv body = sd.substr(1, sd.size() - 2);
  const std::size_t sp = body.find(' ');
  if (sp == sv::npos) return false;
  e.keep("sd_id", body.substr(0, sp));
  sv rest;
  const bool ok = scan_kv(body.substr(sp + 1), [&](sv k, sv v) {
    if (k == "source-address") e.src_ip = v;
    else if (k == "destination-address") e.dst_ip = v;
    else if (k == "source-port") e.has_sport = to_port(v, e.src_port);
    else if (k == "destination-port") e.has_dport = to_port(v, e.dst_port);
    else if (k == "protocol-id") e.proto = proto_from_name(v);
    else if (k == "bytes-from-client") { std::uint64_t x; if (to_u64(v, x)) { e.bytes_out = x; e.has_bytes = true; } }
    else if (k == "bytes-from-server") { std::uint64_t x; if (to_u64(v, x)) { e.bytes_in = x; e.has_bytes = true; } }
    else if (k == "packets-from-client") { std::uint64_t x; if (to_u64(v, x)) { e.pkts_out = x; e.has_pkts = true; } }
    else if (k == "packets-from-server") { std::uint64_t x; if (to_u64(v, x)) { e.pkts_in = x; e.has_pkts = true; } }
    else if (k == "policy-name") e.rule = v;
    else if (k == "application") e.app_name = v;
    else if (k == "reason") e.reason = v;
    else e.keep(k, v);
  }, rest);
  if (!ok) { e.complete = false; e.rest = rest; e.keep("_unparsed", rest); }
  return true;
}

// ---------------------------------------------------------------- Suricata EVE
// A small JSON walker for EVE's shape: flat members plus one level of nested
// objects. Values stay as views (strings without their quotes, still escaped).
struct Json {
  sv s;
  std::size_t i = 0;
  void ws() { while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i; }
  bool str(sv& out) {
    if (i >= s.size() || s[i] != '"') return false;
    const std::size_t a = ++i;
    while (i < s.size() && s[i] != '"') { if (s[i] == '\\') ++i; ++i; }
    if (i >= s.size()) return false;
    out = s.substr(a, i - a);
    ++i;
    return true;
  }
  bool scalar(sv& out) {
    const std::size_t a = i;
    while (i < s.size() && s[i] != ',' && s[i] != '}' && s[i] != ']') ++i;
    out = s.substr(a, i - a);
    while (!out.empty() && out.back() == ' ') out.remove_suffix(1);
    return !out.empty();
  }
};

bool parse_eve(sv s, Event& e) {
  Json j{s};
  if (s.empty() || s[0] != '{') return false;
  e.fmt = Fmt::kSuricataEve;
  e.vendor = "OISF";
  e.product = "Suricata";
  e.class_uid = 4001;
  j.i = 1;
  sv event_type;
  auto member = [&](sv parent, auto&& self) -> bool {
    while (true) {
      j.ws();
      if (j.i < s.size() && s[j.i] == '}') { ++j.i; return true; }
      sv key, val;
      if (!j.str(key)) return false;
      j.ws();
      if (j.i >= s.size() || s[j.i] != ':') return false;
      ++j.i;
      j.ws();
      if (j.i < s.size() && s[j.i] == '{') {
        ++j.i;
        if (!self(key, self)) return false;
      } else if (j.i < s.size() && s[j.i] == '"') {
        if (!j.str(val)) return false;
      } else if (!j.scalar(val)) {
        return false;
      }
      if (!val.empty() || (j.i > 0 && s[j.i - 1] == '"')) {
        if (parent.empty()) {
          if (key == "timestamp") iso_time(val, e);
          else if (key == "src_ip") e.src_ip = val;
          else if (key == "dest_ip") e.dst_ip = val;
          else if (key == "src_port") e.has_sport = to_port(val, e.src_port);
          else if (key == "dest_port") e.has_dport = to_port(val, e.dst_port);
          else if (key == "proto") e.proto = proto_from_name(val);
          else if (key == "event_type") { event_type = val; e.log_name = val; }
          else e.keep(key, val);
        } else if (parent == "alert") {
          if (key == "signature") e.signature = val;
          else if (key == "signature_id") e.sig_uid = val;
          else if (key == "category") e.category = val;
          else if (key == "severity") e.severity_id = val == "1" ? 4 : val == "2" ? 3 : 2;
          else e.keep(key, val, parent);
        } else {
          e.keep(key, val, parent);
        }
      }
      j.ws();
      if (j.i < s.size() && s[j.i] == ',') { ++j.i; continue; }
      if (j.i < s.size() && s[j.i] == '}') { ++j.i; return true; }
      return false;
    }
  };
  if (!member(sv{}, member)) { e.complete = false; e.rest = s.substr(j.i < s.size() ? j.i : s.size()); e.keep("_unparsed", e.rest); }
  if (event_type == "alert") { e.class_uid = 2004; e.activity_id = 1; }
  else e.activity_id = 6;
  return true;
}

// ---------------------------------------------------------------- LEEF
// LEEF:2.0|Vendor|Product|Version|EventID|Delimiter|k=v<delim>k=v
bool parse_leef(sv s, Event& e) {
  sv h[6];
  int n = 0;
  std::size_t a = 0;
  for (std::size_t i = 0; i < s.size() && n < 6; ++i)
    if (s[i] == '|') { h[n++] = s.substr(a, i - a); a = i + 1; }
  const bool v2 = starts(s, "LEEF:2");
  if (n < (v2 ? 6 : 5)) return false;
  e.fmt = Fmt::kLeef;
  e.vendor = h[1];
  e.product = h[2];
  e.sig_uid = h[4];
  e.class_uid = 4001;
  char delim = '\t';
  if (v2) {
    const sv d = h[5];
    if (d.size() == 1) delim = d[0];
    else if (d.size() == 3 && (d[0] == 'x' || d[0] == 'X')) {
      auto hex = [](char c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; };
      delim = static_cast<char>(hex(d[1]) * 16 + hex(d[2]));
    }
  }
  sv attrs = s.substr(a);
  std::size_t i = 0;
  while (i <= attrs.size()) {
    std::size_t j = attrs.find(delim, i);
    if (j == sv::npos) j = attrs.size();
    const sv pair = attrs.substr(i, j - i);
    const std::size_t eq = pair.find('=');
    if (eq != sv::npos) {
      const sv k = pair.substr(0, eq), v = pair.substr(eq + 1);
      if (k == "src") e.src_ip = v;
      else if (k == "dst") e.dst_ip = v;
      else if (k == "srcPort") e.has_sport = to_port(v, e.src_port);
      else if (k == "dstPort") e.has_dport = to_port(v, e.dst_port);
      else if (k == "proto") e.proto = proto_from_name(v);
      else if (k == "action") { e.action_id = v == "allow" ? 1 : 2; e.activity_id = e.action_id == 2 ? 5 : 6; e.keep(k, v); }
      else if (k == "srcBytes") { std::uint64_t x; if (to_u64(v, x)) { e.bytes_out = x; e.has_bytes = true; } }
      else if (k == "dstBytes") { std::uint64_t x; if (to_u64(v, x)) { e.bytes_in = x; e.has_bytes = true; } }
      else if (k == "policy") e.rule = v;
      else if (k == "devTime") {
        std::uint64_t ms = 0;
        if (to_u64(v, ms)) { e.time_ms = static_cast<std::int64_t>(ms); e.has_time = true; e.time_text = v; }
      } else e.keep(k, v);
    } else if (!pair.empty()) {
      e.complete = false;
      e.keep("_unparsed", pair);
    }
    if (j >= attrs.size()) break;
    i = j + 1;
  }
  return true;
}

}  // namespace

bool parse_line(sv line, Event& e) {
  e.reset(line);
  Header h;
  if (!syslog_header(line, e, h)) {
    e.complete = false;
    e.keep("_unparsed", line);
    return false;
  }
  sv m = h.msg;
  bool ok = false;
  if (starts(m, "date=")) ok = parse_fortigate(m, e);
  else if (!h.sd.empty() && starts(h.msgid, "RT_FLOW")) ok = parse_srx(h.sd, h.msgid, e);
  else if (starts(m, "CEF:")) ok = parse_cef(m, e);
  else if (starts(m, "LEEF:")) ok = parse_leef(m, e);
  else if (starts(m, "{")) ok = parse_eve(m, e);
  else if (starts(m, ": %ASA-")) ok = parse_asa(m.substr(2), e);
  else if (starts(m, "%ASA-")) ok = parse_asa(m, e);
  else if (starts(m, "filterlog[")) {
    const std::size_t c = m.find(": ");
    ok = c != sv::npos && parse_filterlog(m.substr(c + 2), e);
  } else if (!m.empty() && m[0] >= '0' && m[0] <= '9' && m.find(",TRAFFIC,") != sv::npos) ok = parse_pan_traffic(m, e);
  else if (starts(m, "CEF:") == false) {
    // an unknown dialect: a Base Event that keeps the message; onboarding
    // (template mining) is what turns these into a parser
    const std::size_t c = m.find("CEF:");
    if (c != sv::npos) ok = parse_cef(m.substr(c), e);
  }
  if (!ok) {
    e.fmt = Fmt::kUnknown;
    e.class_uid = 0;
    e.activity_id = 99;
    e.message = m;
    e.complete = false;
    e.rest = m;
  }
  return ok;
}

std::uint64_t hash64(sv s) {
  // wyhash-style mixing, 8 bytes at a time; not cryptographic
  auto mix = [](std::uint64_t a, std::uint64_t b) {
    const unsigned __int128 r = static_cast<unsigned __int128>(a) * b;
    return static_cast<std::uint64_t>(r) ^ static_cast<std::uint64_t>(r >> 64);
  };
  const std::uint64_t k0 = 0xa0761d6478bd642full, k1 = 0xe7037ed1a0b428dbull;
  std::uint64_t h = 0x9e3779b97f4a7c15ull ^ s.size();
  std::size_t i = 0;
  for (; i + 8 <= s.size(); i += 8) {
    std::uint64_t w;
    std::memcpy(&w, s.data() + i, 8);
    h = mix(h ^ w ^ k0, k1);
  }
  std::uint64_t tail = 0;
  std::memcpy(&tail, s.data() + i, s.size() - i);
  return mix(h ^ tail ^ k1, k0 ^ s.size());
}

}  // namespace lipi
