// Lipi: one script for every perimeter log.
//
// The engine turns one raw log line into one normalised event without copying
// a byte of it: every field is a view into the line, so the line itself is the
// lossless record and every field can say exactly which bytes it came from.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace lipi {

using sv = std::string_view;

enum class Fmt : std::uint8_t {
  kUnknown = 0,
  kFortiGate,
  kPanTraffic,
  kCiscoAsa,
  kCef,
  kPfFilterlog,
  kSrxFlow,
  kSuricataEve,
  kLeef,
  kCount
};

const char* fmt_name(Fmt f);

struct KV {
  sv parent;  // non-empty for a member of a nested object (Suricata "alert")
  sv key;
  sv val;
};

// One normalised event. Scalars are reset per line; the arrays are not cleared,
// only their counts, so reuse costs nothing.
struct Event {
  sv raw;
  Fmt fmt = Fmt::kUnknown;

  sv host, app, time_text;
  std::int64_t time_ms = 0;
  bool has_time = false;
  int tz_min = 330;  // device offset in minutes; IST unless the log says otherwise

  int class_uid = 0;     // OCSF 4001 Network Activity, 2004 Detection Finding, 0 Base Event
  int activity_id = 0;   // OCSF activity within the class
  int action_id = 0;     // 1 Allowed, 2 Denied, 0 Unknown
  int severity_id = 1;   // OCSF 1 Informational .. 5 Critical
  sv src_ip, dst_ip;
  std::uint32_t src_port = 0, dst_port = 0;
  bool has_sport = false, has_dport = false;
  int proto = -1;
  std::uint64_t bytes_out = 0, bytes_in = 0, pkts_out = 0, pkts_in = 0;
  bool has_bytes = false, has_pkts = false;
  sv vendor, product, log_name, rule, app_name, signature, sig_uid, category, message, reason;

  static constexpr int kMaxKV = 96;
  KV unmapped[kMaxKV];
  int n_unmapped = 0;

  bool complete = true;  // every byte of the line was explained by the parser
  sv rest;               // the bytes it could not explain, kept in unmapped too

  void reset(sv line) {
    raw = line;
    fmt = Fmt::kUnknown;
    host = app = time_text = sv{};
    time_ms = 0;
    has_time = false;
    tz_min = 330;
    class_uid = activity_id = action_id = 0;
    severity_id = 1;
    src_ip = dst_ip = sv{};
    src_port = dst_port = 0;
    has_sport = has_dport = false;
    proto = -1;
    bytes_out = bytes_in = pkts_out = pkts_in = 0;
    has_bytes = has_pkts = false;
    vendor = product = log_name = rule = app_name = signature = sig_uid = category = message = reason = sv{};
    n_unmapped = 0;
    complete = true;
    rest = sv{};
  }
  void keep(sv k, sv v, sv parent = sv{}) {
    if (n_unmapped < kMaxKV) unmapped[n_unmapped++] = KV{parent, k, v};
  }
};

// Recognise the format and fill the event. False when no parser claims the line;
// the event is still written, as a Base Event carrying the raw line.
bool parse_line(sv line, Event& e);

// Write the event as one OCSF JSON line. The pointer form is the fast path: the
// caller keeps ocsf_bound(e) bytes free at dst and gets back the new end.
std::size_t ocsf_bound(const Event& e);
char* write_ocsf(const Event& e, char* dst);
void write_ocsf(const Event& e, std::string& out);

// A fast 64-bit hash of the raw line (wyhash-style), for de-duplication and
// for tying the normalised record to its raw bytes.
std::uint64_t hash64(sv s);

}  // namespace lipi
