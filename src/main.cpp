// lipi: normalise perimeter logs to OCSF, and measure doing it.
//
//   lipi normalize <in.log> [--out=FILE] [--threads=N]
//   lipi bench     <in.log> [--threads=N] [--repeat=R] [--parse-only]
//   lipi latency   <in.log> [--sample=N]
//   lipi verify    <in.log>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "lipi.hpp"

using namespace lipi;
using Clock = std::chrono::steady_clock;

namespace {

std::string slurp(const char* path) {
  FILE* f = std::fopen(path, "rb");
  if (!f) { std::fprintf(stderr, "cannot open %s\n", path); std::exit(2); }
  std::fseek(f, 0, SEEK_END);
  const long n = std::ftell(f);
  std::fseek(f, 0, SEEK_SET);
  std::string s(static_cast<std::size_t>(n), '\0');
  const std::size_t got = std::fread(s.data(), 1, s.size(), f);
  std::fclose(f);
  s.resize(got);
  return s;
}

std::vector<sv> lines_of(const std::string& buf) {
  std::vector<sv> v;
  v.reserve(buf.size() / 200 + 16);
  const char* p = buf.data();
  const char* end = p + buf.size();
  while (p < end) {
    const char* nl = static_cast<const char*>(std::memchr(p, '\n', static_cast<std::size_t>(end - p)));
    const char* e = nl ? nl : end;
    const char* t = e;
    if (t > p && t[-1] == '\r') --t;
    if (t > p) v.emplace_back(p, static_cast<std::size_t>(t - p));
    p = e + 1;
  }
  return v;
}

const char* opt(int argc, char** argv, const char* name, const char* def) {
  const std::size_t n = std::strlen(name);
  for (int i = 2; i < argc; ++i)
    if (std::strncmp(argv[i], name, n) == 0 && argv[i][n] == '=') return argv[i] + n + 1;
  return def;
}

bool flag(int argc, char** argv, const char* name) {
  for (int i = 2; i < argc; ++i)
    if (std::strcmp(argv[i], name) == 0) return true;
  return false;
}

struct Counts {
  std::uint64_t events = 0, bytes_in = 0, bytes_out = 0, complete = 0, unknown = 0;
  std::uint64_t per_fmt[static_cast<int>(Fmt::kCount)] = {};
  void add(const Counts& c) {
    events += c.events; bytes_in += c.bytes_in; bytes_out += c.bytes_out; complete += c.complete; unknown += c.unknown;
    for (int i = 0; i < static_cast<int>(Fmt::kCount); ++i) per_fmt[i] += c.per_fmt[i];
  }
};

// One worker: a contiguous slice of lines, its own event and output buffer.
void work(const sv* first, const sv* last, bool write, std::string* sink, Counts* c) {
  Event e;
  constexpr std::size_t kBuf = 8u << 20;
  std::unique_ptr<char[]> buf(new char[kBuf]);
  char* p = buf.get();
  auto flush = [&] {
    const std::size_t n = static_cast<std::size_t>(p - buf.get());
    c->bytes_out += n;
    if (sink) sink->append(buf.get(), n);
    p = buf.get();
  };
  for (const sv* l = first; l != last; ++l) {
    const bool ok = parse_line(*l, e);
    ++c->events;
    c->bytes_in += l->size() + 1;
    c->complete += e.complete;
    c->unknown += !ok;
    ++c->per_fmt[static_cast<int>(e.fmt)];
    if (write) {
      if (static_cast<std::size_t>(buf.get() + kBuf - p) < ocsf_bound(e)) flush();
      p = write_ocsf(e, p);
    }
  }
  flush();
}

Counts run(const std::vector<sv>& lines, int threads, bool write, std::vector<std::string>* sinks) {
  std::vector<Counts> counts(static_cast<std::size_t>(threads));
  std::vector<std::thread> pool;
  const std::size_t n = lines.size();
  for (int t = 0; t < threads; ++t) {
    const std::size_t a = n * static_cast<std::size_t>(t) / static_cast<std::size_t>(threads);
    const std::size_t b = n * static_cast<std::size_t>(t + 1) / static_cast<std::size_t>(threads);
    std::string* sink = sinks ? &(*sinks)[static_cast<std::size_t>(t)] : nullptr;
    pool.emplace_back(work, lines.data() + a, lines.data() + b, write, sink, &counts[static_cast<std::size_t>(t)]);
  }
  for (auto& th : pool) th.join();
  Counts all;
  for (auto& c : counts) all.add(c);
  return all;
}

void report_formats(const Counts& c) {
  for (int i = 1; i < static_cast<int>(Fmt::kCount); ++i)
    if (c.per_fmt[i]) std::printf("  %-18s %10llu\n", fmt_name(static_cast<Fmt>(i)), static_cast<unsigned long long>(c.per_fmt[i]));
  if (c.per_fmt[0]) std::printf("  %-18s %10llu\n", "unknown", static_cast<unsigned long long>(c.per_fmt[0]));
}

int cmd_bench(int argc, char** argv) {
  const std::string buf = slurp(argv[2]);
  const auto lines = lines_of(buf);
  const int threads = std::max(1, std::atoi(opt(argc, argv, "--threads", "1")));
  const int repeat = std::max(1, std::atoi(opt(argc, argv, "--repeat", "3")));
  const bool write = !flag(argc, argv, "--parse-only");
  run(lines, threads, write, nullptr);  // warm the caches and the allocator
  double best = 1e100;
  Counts c;
  for (int r = 0; r < repeat; ++r) {
    const auto t0 = Clock::now();
    c = run(lines, threads, write, nullptr);
    const double s = std::chrono::duration<double>(Clock::now() - t0).count();
    best = std::min(best, s);
  }
  std::printf("lines        %llu (%.1f MB)\n", static_cast<unsigned long long>(c.events), static_cast<double>(c.bytes_in) / 1e6);
  std::printf("threads      %d\n", threads);
  std::printf("mode         %s\n", write ? "parse + normalise + OCSF JSON" : "parse + normalise");
  std::printf("best of %d    %.3f s\n", repeat, best);
  std::printf("events/s     %.0f\n", static_cast<double>(c.events) / best);
  std::printf("events/s/thread %.0f\n", static_cast<double>(c.events) / best / threads);
  std::printf("input MB/s   %.1f\n", static_cast<double>(c.bytes_in) / best / 1e6);
  if (write) std::printf("output MB/s  %.1f (%.2f output bytes per input byte)\n", static_cast<double>(c.bytes_out) / best / 1e6, static_cast<double>(c.bytes_out) / static_cast<double>(c.bytes_in));
  std::printf("fully parsed %.4f%% (%llu of %llu), unknown format %llu\n", 100.0 * static_cast<double>(c.complete) / static_cast<double>(c.events),
              static_cast<unsigned long long>(c.complete), static_cast<unsigned long long>(c.events), static_cast<unsigned long long>(c.unknown));
  report_formats(c);
  return 0;
}

int cmd_normalize(int argc, char** argv) {
  const std::string buf = slurp(argv[2]);
  const auto lines = lines_of(buf);
  const int threads = std::max(1, std::atoi(opt(argc, argv, "--threads", "1")));
  std::vector<std::string> sinks(static_cast<std::size_t>(threads));
  // OCSF JSON with the raw line kept runs to about four times the input; room
  // is made once so the buffers never regrow and copy
  for (auto& s : sinks) s.reserve(buf.size() * 4 / static_cast<std::size_t>(threads) + (1u << 24));
  const Counts c = run(lines, threads, true, &sinks);
  const char* out = opt(argc, argv, "--out", "-");
  FILE* f = std::strcmp(out, "-") == 0 ? stdout : std::fopen(out, "wb");
  if (!f) { std::fprintf(stderr, "cannot write %s\n", out); return 2; }
  for (auto& s : sinks) std::fwrite(s.data(), 1, s.size(), f);
  if (f != stdout) std::fclose(f);
  std::fprintf(stderr, "normalised %llu events, %llu unknown\n", static_cast<unsigned long long>(c.events), static_cast<unsigned long long>(c.unknown));
  return 0;
}

// Per-event latency: each event is timed on its own, parse through JSON. The
// clock read costs a few tens of nanoseconds and is included, so these are
// upper bounds.
int cmd_latency(int argc, char** argv) {
  const std::string buf = slurp(argv[2]);
  const auto lines = lines_of(buf);
  const std::size_t sample = std::min<std::size_t>(lines.size(), static_cast<std::size_t>(std::atoll(opt(argc, argv, "--sample", "200000"))));
  Event e;
  std::unique_ptr<char[]> out(new char[1 << 20]);
  std::vector<std::uint32_t> ns(sample);
  for (std::size_t i = 0; i < sample; ++i) { parse_line(lines[i], e); write_ocsf(e, out.get()); }
  for (std::size_t i = 0; i < sample; ++i) {
    const auto t0 = Clock::now();
    parse_line(lines[i], e);
    write_ocsf(e, out.get());
    const auto t1 = Clock::now();
    ns[i] = static_cast<std::uint32_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());
  }
  std::sort(ns.begin(), ns.end());
  auto q = [&](double p) { return ns[std::min(ns.size() - 1, static_cast<std::size_t>(p * static_cast<double>(ns.size())))]; };
  std::printf("events %zu, per-event parse + normalise + OCSF JSON, one thread, nanoseconds\n", sample);
  std::printf("p50 %u  p90 %u  p99 %u  p99.9 %u  max %u\n", q(0.50), q(0.90), q(0.99), q(0.999), ns.back());
  return 0;
}

// Lossless and traceable, checked rather than assumed: every normalised field
// must be a view into its own raw line (so it can point at its bytes), and every
// line must either be fully explained or carry its unexplained bytes.
int cmd_verify(int, char** argv) {
  const std::string buf = slurp(argv[2]);
  const auto lines = lines_of(buf);
  Event e;
  std::uint64_t fields = 0, outside = 0, unexplained_dropped = 0, complete = 0;
  auto inside = [&](sv f) {
    if (f.empty()) return;
    ++fields;
    const char* a = e.raw.data();
    const char* b = a + e.raw.size();
    if (f.data() < a || f.data() + f.size() > b) ++outside;
  };
  for (const sv l : lines) {
    parse_line(l, e);
    complete += e.complete;
    // Values must be views into the line. Keys of positional formats (PAN-OS,
    // pfSense) are the vendor's field names, supplied by the parser, so only
    // values are held to this rule.
    for (sv f : {e.host, e.app, e.time_text, e.src_ip, e.dst_ip, e.log_name, e.rule,
                 e.app_name, e.signature, e.sig_uid, e.category, e.message, e.reason})
      inside(f);
    for (int i = 0; i < e.n_unmapped; ++i) inside(e.unmapped[i].val);
    if (!e.complete && e.rest.empty()) ++unexplained_dropped;
  }
  std::printf("lines %zu\n", lines.size());
  std::printf("fully parsed %llu (%.4f%%)\n", static_cast<unsigned long long>(complete), 100.0 * static_cast<double>(complete) / static_cast<double>(lines.size()));
  std::printf("field views checked %llu, pointing outside their raw line %llu\n", static_cast<unsigned long long>(fields), static_cast<unsigned long long>(outside));
  std::printf("lines with unexplained bytes not carried %llu\n", static_cast<unsigned long long>(unexplained_dropped));
  return outside == 0 && unexplained_dropped == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 3) {
    std::fprintf(stderr, "usage: lipi normalize|bench|latency|verify <in.log> [options]\n");
    return 2;
  }
  const std::string cmd = argv[1];
  if (cmd == "bench") return cmd_bench(argc, argv);
  if (cmd == "normalize") return cmd_normalize(argc, argv);
  if (cmd == "latency") return cmd_latency(argc, argv);
  if (cmd == "verify") return cmd_verify(argc, argv);
  std::fprintf(stderr, "unknown command %s\n", cmd.c_str());
  return 2;
}
