// OCSF output: one JSON object per event, written straight into a reused buffer.
//
// Three kinds of text meet here and each needs different handling:
//   raw bytes    must come out byte-exact, so they are only JSON-escaped;
//   vendor text  carries the vendor's own escapes (CEF \= \| \\, RFC 5424 \" \]),
//                which are undone before JSON escaping;
//   JSON text    from a JSON source is already escaped and is copied verbatim.
#include <charconv>
#include <cstring>

#include "lipi.hpp"

namespace lipi {
namespace {

enum class Text { kRaw, kVendor, kJson };

// Output goes through a bare pointer: the caller guarantees room for the worst
// case (every byte escaped six ways) before each event, so no append has to
// check capacity. That check, repeated a hundred times per event, was costing
// more than the escaping itself.
struct Out {
  char* p;
  Out& operator+=(char c) { *p++ = c; return *this; }
  Out& operator+=(const char* z) { const std::size_t n = std::strlen(z); std::memcpy(p, z, n); p += n; return *this; }
  void append(const char* d, std::size_t n) { std::memcpy(p, d, n); p += n; }
};

inline void put(Out& o, sv s) { o.append(s.data(), s.size()); }

inline void put_u64(Out& o, std::uint64_t v) {
  char b[24];
  auto r = std::to_chars(b, b + sizeof b, v);
  o.append(b, static_cast<std::size_t>(r.ptr - b));
}

inline void put_i64(Out& o, std::int64_t v) {
  char b[24];
  auto r = std::to_chars(b, b + sizeof b, v);
  o.append(b, static_cast<std::size_t>(r.ptr - b));
}

inline void escape_char(Out& o, char c) {
  static const char* kHex = "0123456789abcdef";
  switch (c) {
    case '"': o += "\\\""; return;
    case '\\': o += "\\\\"; return;
    case '\n': o += "\\n"; return;
    case '\r': o += "\\r"; return;
    case '\t': o += "\\t"; return;
    default:
      if (static_cast<unsigned char>(c) < 0x20) {
        o += "\\u00";
        o += kHex[(c >> 4) & 15];
        o += kHex[c & 15];
      } else {
        o += c;
      }
  }
}

// Bytes that need attention inside a JSON string: quote, backslash and the
// control characters. A table lookup per byte keeps the common case (a clean
// run) to one load and one well-predicted branch.
struct EscapeTable {
  bool t[256];
  constexpr EscapeTable() : t() {
    for (int c = 0; c < 0x20; ++c) t[c] = true;
    t[static_cast<unsigned char>('"')] = true;
    t[static_cast<unsigned char>('\\')] = true;
  }
};
constexpr EscapeTable kEsc;

void put_str(Out& o, sv s, Text t) {
  o += '"';
  if (t == Text::kJson) {
    put(o, s);
    o += '"';
    return;
  }
  const char* p = s.data();
  const std::size_t n = s.size();
  std::size_t run = 0, i = 0;
  while (i < n) {
    if (!kEsc.t[static_cast<unsigned char>(p[i])]) { ++i; continue; }
    o.append(p + run, i - run);
    char c = p[i];
    if (t == Text::kVendor && c == '\\' && i + 1 < n &&
        (p[i + 1] == '=' || p[i + 1] == '|' || p[i + 1] == ']' || p[i + 1] == '"' || p[i + 1] == '\\'))
      c = p[++i];
    escape_char(o, c);
    run = ++i;
  }
  o.append(p + run, n - run);
  o += '"';
}

inline void key(Out& o, const char* k, bool& first) {
  if (!first) o += ',';
  first = false;
  o += '"';
  o += k;
  o += "\":";
}

}  // namespace

std::size_t ocsf_bound(const Event& e) { return 24 * e.raw.size() + 64 * static_cast<std::size_t>(e.n_unmapped) + 4096; }

char* write_ocsf(const Event& e, char* dst) {
  Out o{dst};
  const Text vt = e.fmt == Fmt::kSuricataEve ? Text::kJson : Text::kVendor;
  bool first = true;
  o += '{';
  key(o, "class_uid", first); put_i64(o, e.class_uid);
  key(o, "category_uid", first); put_i64(o, e.class_uid / 1000);
  key(o, "activity_id", first); put_i64(o, e.activity_id);
  key(o, "type_uid", first); put_i64(o, static_cast<std::int64_t>(e.class_uid) * 100 + e.activity_id);
  key(o, "severity_id", first); put_i64(o, e.severity_id);
  if (e.has_time) { key(o, "time", first); put_i64(o, e.time_ms); }
  key(o, "timezone_offset", first); put_i64(o, e.tz_min);

  key(o, "metadata", first);
  {
    bool f = true;
    o += '{';
    key(o, "version", f); o += "\"1.3.0\"";
    key(o, "product", f);
    o += "{\"vendor_name\":"; put_str(o, e.vendor.empty() ? sv("unknown") : e.vendor, Text::kVendor);
    o += ",\"name\":"; put_str(o, e.product.empty() ? sv(fmt_name(e.fmt)) : e.product, Text::kVendor);
    o += '}';
    if (!e.log_name.empty()) { key(o, "log_name", f); put_str(o, e.log_name, vt); }
    if (!e.time_text.empty()) { key(o, "original_time", f); put_str(o, e.time_text, vt); }
    key(o, "extension", f); o += "{\"name\":\"lipi\",\"version\":\"0.1\"}";
    o += '}';
  }
  if (!e.src_ip.empty() || e.has_sport) {
    key(o, "src_endpoint", first);
    o += '{';
    bool f = true;
    if (!e.src_ip.empty()) { key(o, "ip", f); put_str(o, e.src_ip, vt); }
    if (e.has_sport) { key(o, "port", f); put_u64(o, e.src_port); }
    o += '}';
  }
  if (!e.dst_ip.empty() || e.has_dport) {
    key(o, "dst_endpoint", first);
    o += '{';
    bool f = true;
    if (!e.dst_ip.empty()) { key(o, "ip", f); put_str(o, e.dst_ip, vt); }
    if (e.has_dport) { key(o, "port", f); put_u64(o, e.dst_port); }
    o += '}';
  }
  if (e.proto >= 0) {
    key(o, "connection_info", first);
    o += "{\"protocol_num\":"; put_i64(o, e.proto);
    o += '}';
  }
  if (e.has_bytes || e.has_pkts) {
    key(o, "traffic", first);
    o += '{';
    bool f = true;
    if (e.has_bytes) { key(o, "bytes_out", f); put_u64(o, e.bytes_out); key(o, "bytes_in", f); put_u64(o, e.bytes_in); }
    if (e.has_pkts) { key(o, "packets_out", f); put_u64(o, e.pkts_out); key(o, "packets_in", f); put_u64(o, e.pkts_in); }
    o += '}';
  }
  if (e.action_id) { key(o, "action_id", first); put_i64(o, e.action_id); }
  if (!e.host.empty()) { key(o, "device", first); o += "{\"hostname\":"; put_str(o, e.host, vt); o += '}'; }
  if (!e.app_name.empty()) { key(o, "app_name", first); put_str(o, e.app_name, vt); }
  if (e.class_uid == 2004 || !e.signature.empty() || !e.rule.empty()) {
    key(o, "finding_info", first);
    o += '{';
    bool f = true;
    if (!e.signature.empty()) { key(o, "title", f); put_str(o, e.signature, vt); }
    if (!e.sig_uid.empty()) { key(o, "uid", f); put_str(o, e.sig_uid, vt); }
    if (!e.category.empty()) { key(o, "types", f); o += '['; put_str(o, e.category, vt); o += ']'; }
    if (!e.rule.empty()) { key(o, "related_policy", f); put_str(o, e.rule, vt); }
    o += '}';
  }
  if (!e.message.empty()) { key(o, "message", first); put_str(o, e.message, vt); }
  if (!e.reason.empty()) { key(o, "status_detail", first); put_str(o, e.reason, vt); }
  if (e.n_unmapped) {
    key(o, "unmapped", first);
    o += '{';
    for (int i = 0; i < e.n_unmapped; ++i) {
      if (i) o += ',';
      const KV& kv = e.unmapped[i];
      o += '"';
      if (!kv.parent.empty()) { put(o, kv.parent); o += '.'; }
      put(o, kv.key);
      o += "\":";
      put_str(o, kv.val, vt);
    }
    o += '}';
  }
  key(o, "raw_data", first); put_str(o, e.raw, Text::kRaw);
  key(o, "raw_data_size", first); put_u64(o, e.raw.size());
  key(o, "raw_data_hash", first);
  {
    static const char* kHex = "0123456789abcdef";
    std::uint64_t h = hash64(e.raw);
    char b[16];
    for (int i = 15; i >= 0; --i) { b[i] = kHex[h & 15]; h >>= 4; }
    o += "{\"algorithm_id\":99,\"algorithm\":\"wyhash64\",\"value\":\"";
    o.append(b, 16);
    o += "\"}";
  }
  o += "}\n";
  return o.p;
}

void write_ocsf(const Event& e, std::string& out) {
  const std::size_t old = out.size();
  out.resize(old + ocsf_bound(e));
  char* end = write_ocsf(e, out.data() + old);
  out.resize(static_cast<std::size_t>(end - out.data()));
}

}  // namespace lipi
