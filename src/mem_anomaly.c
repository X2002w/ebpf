// mem_anomaly.c — 内存抖动异常检测用户态
//
// eBPF pid_mem:   缺页洪流探测器 — 按进程实时计数 raw/completed, 不区分主次
// /proc/<pid>/stat:  权威主次 — 读 min_flt(字段10)/maj_flt(字段12) 窗口增量
// eBPF global_mem:  kswapd / 直接回收 / lru 回收 / OOM 等系统级信号
// /proc/meminfo, /proc/vmstat:  容量快照与系统级速率

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <stdint.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "mem_anomaly.skel.h"
#include "../include/mem_anomaly.h"
#include "../include/report_json.h"
#include "../include/report_md.h"
#include "../include/utils.h"

#define DEFAULT_INTERVAL   3
#define MAX_TOP            5
#define MAX_ROWS           256

#define DEF_AVAIL_PCT_LO   10.0
#define DEF_MAJFAULT_HI    200.0
#define DEF_REFAULT_HI     1000.0
#define DEF_SWAPIN_HI      500.0
#define DIRECT_STALL_HI_MS 1.0
#define RETRY_HI_PS        50.0
#define FAULT_HI_PS        5000.0
#define CONSIST_TOL_PCT    15.0

#define MAX_FLT_CACHE 8192
#define FLT_CACHE_TTL 4

struct mem_proc_stats {
  unsigned long long fault_raw;
  unsigned long long fault_completed;
  unsigned long long direct_reclaim_cnt;
  unsigned long long direct_reclaim_ns;
  unsigned long long reclaimed_pages;
  unsigned long long fault_count;
  unsigned long long last_fault_ts;
};

struct mem_sys_stats {
  unsigned long long kswapd_wake_count;
  unsigned long long kswapd_active_ns;
  unsigned long long direct_reclaim_cnt;
  unsigned long long direct_reclaim_ns;
  unsigned long long reclaimed_pages;
  unsigned long long page_scan;
  unsigned long long page_steal;
  unsigned long long oom_kills;
  unsigned int last_oom_pid;
};

struct meminfo {
  unsigned long long total, free, available, buffers, cached;
  unsigned long long swaptotal, swapfree;
  unsigned long long dirty, writeback, anon, sreclaimable, shmem, mapped;
};

struct vmstat {
  unsigned long long pgfault, pgmajfault;
  unsigned long long pswpin, pswpout;
  unsigned long long ws_refault, ws_refault_anon, ws_refault_file;
  unsigned long long pgscan_direct, pgscan_kswapd;
  unsigned long long oom_kill;
};

struct win_rates {
  double pgfault_ps, pgmajfault_ps;
  double pswpin_ps, pswpout_ps;
  double refault_ps;
  double pgscan_direct_ps;
  unsigned long long oom_delta;
};

struct proc_row {
  unsigned int tgid;
  struct mem_proc_stats st;
  unsigned long long minflt_d;
  unsigned long long majflt_d;
  int matched;
  char comm[16];
};

struct flt_audit {
  unsigned long long raw;
  unsigned long long completed;
  unsigned long long retry;
  unsigned long long raw_matched;
  unsigned long long procflt_matched;
  int matched_count;
};

// /proc/<pid>/stat 主次增量缓存
struct flt_prev {
  unsigned int pid;
  unsigned int last_gen;
  unsigned long long minflt, majflt;
};

// BPF map 值增量缓存 — 避免 reset map 导致进程消失
struct bpf_prev {
  unsigned int pid;
  unsigned int last_gen;
  unsigned long long fault_raw;
  unsigned long long fault_completed;
  unsigned long long direct_reclaim_cnt;
  unsigned long long direct_reclaim_ns;
  unsigned long long reclaimed_pages;
};

static struct flt_prev g_flt[MAX_FLT_CACHE];
static int g_flt_n;
static struct bpf_prev g_bpf_prev[MAX_FLT_CACHE];
static int g_bpf_prev_n;
static unsigned int g_gen;

static unsigned long long sub_clamp(unsigned long long a, unsigned long long b)
{
  return a > b ? a - b : 0;
}

static double pct(unsigned long long part, unsigned long long whole)
{
  return whole ? (double)part / (double)whole * 100.0 : 0.0;
}

static int read_proc_flt(unsigned int pid,
                         unsigned long long *minflt,
                         unsigned long long *majflt)
{
  char path[64];
  snprintf(path, sizeof(path), "/proc/%u/stat", pid);
  FILE *f = fopen(path, "r");
  if (!f) return -1;
  char buf[1024];
  char *ok = fgets(buf, sizeof(buf), f);
  fclose(f);
  if (!ok) return -1;

  char *rp = strrchr(buf, ')');
  if (!rp) return -1;
  rp++;

  unsigned long long vals[16];
  int n = 0;
  char *tok = strtok(rp, " \t\n");
  while (tok && n < 16) {
    vals[n++] = strtoull(tok, NULL, 10);
    tok = strtok(NULL, " \t\n");
  }
  if (n <= 9) return -1;
  *minflt = vals[7];
  *majflt = vals[9];
  return 0;
}

static int flt_delta(unsigned int pid,
                     unsigned long long cur_min, unsigned long long cur_maj,
                     unsigned long long *dmin, unsigned long long *dmaj)
{
  for (int i = 0; i < g_flt_n; i++) {
    if (g_flt[i].pid == pid) {
      *dmin = sub_clamp(cur_min, g_flt[i].minflt);
      *dmaj = sub_clamp(cur_maj, g_flt[i].majflt);
      g_flt[i].minflt = cur_min;
      g_flt[i].majflt = cur_maj;
      g_flt[i].last_gen = g_gen;
      return 1;
    }
  }
  if (g_flt_n < MAX_FLT_CACHE) {
    g_flt[g_flt_n].pid = pid;
    g_flt[g_flt_n].minflt = cur_min;
    g_flt[g_flt_n].majflt = cur_maj;
    g_flt[g_flt_n].last_gen = g_gen;
    g_flt_n++;
  }
  *dmin = 0;
  *dmaj = 0;
  return 0;
}

static void flt_cache_gc(void)
{
  int w = 0;
  for (int i = 0; i < g_flt_n; i++) {
    if (g_gen - g_flt[i].last_gen <= FLT_CACHE_TTL) {
      if (w != i) g_flt[w] = g_flt[i];
      w++;
    }
  }
  g_flt_n = w;

  w = 0;
  for (int i = 0; i < g_bpf_prev_n; i++) {
    if (g_gen - g_bpf_prev[i].last_gen <= FLT_CACHE_TTL) {
      if (w != i) g_bpf_prev[w] = g_bpf_prev[i];
      w++;
    }
  }
  g_bpf_prev_n = w;
}

// BPF map 增量 — 与 flt_delta 同理, 首窗口返回 d_*=0
static int bpf_delta(unsigned int pid,
                     unsigned long long cur_raw, unsigned long long cur_comp,
                     unsigned long long cur_drc, unsigned long long cur_drn,
                     unsigned long long cur_rp,
                     unsigned long long *d_raw, unsigned long long *d_comp,
                     unsigned long long *d_drc, unsigned long long *d_drn,
                     unsigned long long *d_rp)
{
  for (int i = 0; i < g_bpf_prev_n; i++) {
    if (g_bpf_prev[i].pid == pid) {
      *d_raw = sub_clamp(cur_raw, g_bpf_prev[i].fault_raw);
      *d_comp = sub_clamp(cur_comp, g_bpf_prev[i].fault_completed);
      *d_drc = sub_clamp(cur_drc, g_bpf_prev[i].direct_reclaim_cnt);
      *d_drn = sub_clamp(cur_drn, g_bpf_prev[i].direct_reclaim_ns);
      *d_rp  = sub_clamp(cur_rp, g_bpf_prev[i].reclaimed_pages);
      g_bpf_prev[i].fault_raw = cur_raw;
      g_bpf_prev[i].fault_completed = cur_comp;
      g_bpf_prev[i].direct_reclaim_cnt = cur_drc;
      g_bpf_prev[i].direct_reclaim_ns = cur_drn;
      g_bpf_prev[i].reclaimed_pages = cur_rp;
      g_bpf_prev[i].last_gen = g_gen;
      return 1;
    }
  }
  if (g_bpf_prev_n < MAX_FLT_CACHE) {
    g_bpf_prev[g_bpf_prev_n].pid = pid;
    g_bpf_prev[g_bpf_prev_n].fault_raw = cur_raw;
    g_bpf_prev[g_bpf_prev_n].fault_completed = cur_comp;
    g_bpf_prev[g_bpf_prev_n].direct_reclaim_cnt = cur_drc;
    g_bpf_prev[g_bpf_prev_n].direct_reclaim_ns = cur_drn;
    g_bpf_prev[g_bpf_prev_n].reclaimed_pages = cur_rp;
    g_bpf_prev[g_bpf_prev_n].last_gen = g_gen;
    g_bpf_prev_n++;
  }
  *d_raw = 0; *d_comp = 0; *d_drc = 0; *d_drn = 0; *d_rp = 0;
  return 0;
}


// /proc 解析 

static int line_kv(const char *line, const char *key, unsigned long long *out)
{
  size_t klen = strlen(key);
  if (strncmp(line, key, klen) != 0) return 0;
  char c = line[klen];
  if (c != ':' && c != ' ' && c != '\t') return 0;
  const char *p = line + klen;
  while (*p && (*p == ':' || *p == ' ' || *p == '\t')) p++;
  return sscanf(p, "%llu", out) == 1;
}

static void read_meminfo(struct meminfo *m)
{
  memset(m, 0, sizeof(*m));
  int have_avail = 0;
  FILE *f = fopen("/proc/meminfo", "r");
  if (!f) return;
  char line[256];
  while (fgets(line, sizeof(line), f)) {
    if (line_kv(line, "MemTotal", &m->total)) continue;
    if (line_kv(line, "MemFree", &m->free)) continue;
    if (line_kv(line, "MemAvailable", &m->available)) { have_avail = 1; continue; }
    if (line_kv(line, "Buffers", &m->buffers)) continue;
    if (line_kv(line, "Cached", &m->cached)) continue;
    if (line_kv(line, "SwapTotal", &m->swaptotal)) continue;
    if (line_kv(line, "SwapFree", &m->swapfree)) continue;
    if (line_kv(line, "Dirty", &m->dirty)) continue;
    if (line_kv(line, "Writeback", &m->writeback)) continue;
    if (line_kv(line, "AnonPages", &m->anon)) continue;
    if (line_kv(line, "SReclaimable", &m->sreclaimable)) continue;
    if (line_kv(line, "Shmem", &m->shmem)) continue;
    if (line_kv(line, "Mapped", &m->mapped)) continue;
  }
  fclose(f);
  if (!have_avail)
    m->available = m->free + m->buffers + m->cached + m->sreclaimable;
}

static void read_vmstat(struct vmstat *v)
{
  memset(v, 0, sizeof(*v));
  FILE *f = fopen("/proc/vmstat", "r");
  if (!f) return;
  char line[256];
  while (fgets(line, sizeof(line), f)) {
    if (line_kv(line, "pgfault", &v->pgfault)) continue;
    if (line_kv(line, "pgmajfault", &v->pgmajfault)) continue;
    if (line_kv(line, "pswpin", &v->pswpin)) continue;
    if (line_kv(line, "pswpout", &v->pswpout)) continue;
    if (line_kv(line, "workingset_refault_anon", &v->ws_refault_anon)) continue;
    if (line_kv(line, "workingset_refault_file", &v->ws_refault_file)) continue;
    if (line_kv(line, "workingset_refault", &v->ws_refault)) continue;
    if (line_kv(line, "pgscan_direct", &v->pgscan_direct)) continue;
    if (line_kv(line, "pgscan_kswapd", &v->pgscan_kswapd)) continue;
    if (line_kv(line, "oom_kill", &v->oom_kill)) continue;
  }
  fclose(f);
}

static unsigned long long refault_total(const struct vmstat *v)
{
  unsigned long long split = v->ws_refault_anon + v->ws_refault_file;
  return split ? split : v->ws_refault;
}

static void compute_rates(const struct vmstat *now, const struct vmstat *prev,
                          double interval_s, struct win_rates *r)
{
  memset(r, 0, sizeof(*r));
  if (interval_s <= 0) return;
  r->pgfault_ps = sub_clamp(now->pgfault, prev->pgfault) / interval_s;
  r->pgmajfault_ps = sub_clamp(now->pgmajfault, prev->pgmajfault) / interval_s;
  r->pswpin_ps = sub_clamp(now->pswpin, prev->pswpin) / interval_s;
  r->pswpout_ps = sub_clamp(now->pswpout, prev->pswpout) / interval_s;
  r->refault_ps = sub_clamp(refault_total(now), refault_total(prev)) / interval_s;
  r->pgscan_direct_ps = sub_clamp(now->pgscan_direct, prev->pgscan_direct) / interval_s;
  r->oom_delta = sub_clamp(now->oom_kill, prev->oom_kill);
}


// eBPF map 读取 
static void read_sys_stats(int fd, struct mem_sys_stats *out)
{
  __u32 key = 0;
  memset(out, 0, sizeof(*out));
  bpf_map_lookup_elem(fd, &key, out);
}

static int cmp_proc(const void *a, const void *b)
{
  const struct proc_row *x = (const struct proc_row *)a;
  const struct proc_row *y = (const struct proc_row *)b;
  if (x->majflt_d != y->majflt_d)
    return x->majflt_d < y->majflt_d ? 1 : -1;
  if (x->st.direct_reclaim_ns != y->st.direct_reclaim_ns)
    return x->st.direct_reclaim_ns < y->st.direct_reclaim_ns ? 1 : -1;
  if (x->st.fault_raw != y->st.fault_raw)
    return x->st.fault_raw < y->st.fault_raw ? 1 : -1;
  return 0;
}

static int read_proc_rows(int fd, struct proc_row *rows, int max_rows)
{
  __u32 key = 0, next_key;
  int n = 0;

  while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
    struct mem_proc_stats st = {};
    if (bpf_map_lookup_elem(fd, &next_key, &st) != 0) {
      key = next_key;
      continue;
    }

    if (n < max_rows) {
      rows[n].tgid = next_key;
      rows[n].st = st;
      rows[n].minflt_d = 0;
      rows[n].majflt_d = 0;
      rows[n].matched = 0;
      read_comm(next_key, rows[n].comm, sizeof(rows[n].comm));
      n++;
    }
    key = next_key;
  }
  return n;
}

static void enrich_and_audit(struct proc_row *rows, int n, struct flt_audit *au)
{
  memset(au, 0, sizeof(*au));
  for (int i = 0; i < n; i++) {
    unsigned long long cmin = 0, cmaj = 0, dmin = 0, dmaj = 0;
    int matched = 0;
    if (read_proc_flt(rows[i].tgid, &cmin, &cmaj) == 0)
      matched = flt_delta(rows[i].tgid, cmin, cmaj, &dmin, &dmaj);

    rows[i].minflt_d = dmin;
    rows[i].majflt_d = dmaj;
    rows[i].matched = matched;

    // BPF 累积值 → 窗口增量
    unsigned long long abs_raw = rows[i].st.fault_raw;
    unsigned long long abs_comp = rows[i].st.fault_completed;
    unsigned long long abs_drc = rows[i].st.direct_reclaim_cnt;
    unsigned long long abs_drn = rows[i].st.direct_reclaim_ns;
    unsigned long long abs_rp  = rows[i].st.reclaimed_pages;

    unsigned long long d_raw, d_comp, d_drc, d_drn, d_rp;
    bpf_delta(rows[i].tgid, abs_raw, abs_comp, abs_drc, abs_drn, abs_rp,
              &d_raw, &d_comp, &d_drc, &d_drn, &d_rp);

    rows[i].st.fault_raw = d_raw;
    rows[i].st.fault_completed = d_comp;
    rows[i].st.direct_reclaim_cnt = d_drc;
    rows[i].st.direct_reclaim_ns = d_drn;
    rows[i].st.reclaimed_pages = d_rp;

    unsigned long long retry = sub_clamp(d_raw, d_comp);
    au->raw += d_raw;
    au->completed += d_comp;
    au->retry += retry;
    if (matched) {
      au->raw_matched += d_raw;
      au->procflt_matched += dmin + dmaj;
      au->matched_count++;
    }
  }
}

// 报告输出 
static const char *consist_label(const struct flt_audit *au, double *dev_pct)
{
  *dev_pct = 0.0;
  if (au->matched_count == 0) return "样本不足(本窗口无可对账进程)";
  if (au->raw_matched == 0 && au->procflt_matched == 0)
    return "样本不足(窗口内无缺页)";
  unsigned long long a = au->raw_matched, b = au->procflt_matched;
  unsigned long long hi = a > b ? a : b;
  unsigned long long lo = a > b ? b : a;
  *dev_pct = hi ? (double)(hi - lo) / (double)hi * 100.0 : 0.0;
  return (*dev_pct <= CONSIST_TOL_PCT) ? "≈一致" : "偏差偏大(采样窗口错位/竞态)";
}

static void print_overview(FILE *out, const struct meminfo *m,
                           const struct mem_sys_stats *sys,
                           const struct win_rates *r,
                           const struct flt_audit *au,
                           unsigned long long tot_reclaim_ns,
                           unsigned long long tot_reclaim_cnt,
                           double interval_s)
{
  char ts[32];
  iso_timestamp(ts, sizeof(ts));

  double avail_pct = pct(m->available, m->total);
  unsigned long long swap_used = sub_clamp(m->swaptotal, m->swapfree);
  double swap_used_pct = pct(swap_used, m->swaptotal);
  double avg_stall_ms = tot_reclaim_cnt
    ? (double)tot_reclaim_ns / (double)tot_reclaim_cnt / 1e6 : 0.0;

  char oom_comm[16] = "";
  if (sys->oom_kills && sys->last_oom_pid)
    read_comm(sys->last_oom_pid, oom_comm, sizeof(oom_comm));

  fprintf(out,
    "======================================================================\n"
    "  内存抖动观测 — 系统内存报告\n"
    "======================================================================\n"
    "  时间窗口: %s  (采样间隔 %.1fs)\n"
    "----------------------------------------------------------------------\n\n",
    ts, interval_s);

  fprintf(out,
    "  容量快照:\n"
    "    总内存:     %8.1f GB\n"
    "    可用内存:   %8.1f GB  (%.1f%%)\n"
    "    空闲:       %8.1f GB\n"
    "    页缓存:     %8.1f GB   (Cached)\n"
    "    匿名页:     %8.1f GB   (AnonPages)\n"
    "    脏页/回写:  %8.1f / %.1f MB\n"
    "    Swap 使用:  %8.1f / %.1f GB  (%.1f%%)\n\n",
    m->total / 1048576.0,
    m->available / 1048576.0, avail_pct,
    m->free / 1048576.0,
    m->cached / 1048576.0,
    m->anon / 1048576.0,
    m->dirty / 1024.0, m->writeback / 1024.0,
    swap_used / 1048576.0, m->swaptotal / 1048576.0, swap_used_pct);

  fprintf(out,
    "  缺页与回收活动 (本窗口速率 / 计数):\n"
    "    缺页总计:       %10.0f 次/s   (/proc/vmstat pgfault)\n"
    "    major fault:    %10.0f 次/s   (/proc/vmstat pgmajfault)\n"
    "    换入 pswpin:    %10.0f 页/s\n"
    "    换出 pswpout:   %10.0f 页/s\n"
    "    refault:        %10.0f 页/s   (回收后又被立即读回)\n"
    "    kswapd 唤醒:    %10llu 次\n"
    "    直接回收:       %10llu 次   (平均阻塞 %.2f ms)\n"
    "    回收扫描/回收:  %llu / %llu 页\n"
    "    OOM 杀进程:     %10llu 次%s%s\n\n",
    r->pgfault_ps, r->pgmajfault_ps,
    r->pswpin_ps, r->pswpout_ps, r->refault_ps,
    sys->kswapd_wake_count,
    sys->direct_reclaim_cnt, avg_stall_ms,
    sys->page_scan, sys->page_steal,
    sys->oom_kills,
    sys->oom_kills ? "  <- 最近: " : "",
    sys->oom_kills ? oom_comm : "");

  double dev_pct = 0.0;
  const char *consist = consist_label(au, &dev_pct);
  double retry_ps = au->retry / interval_s;

  fprintf(out,
    "  缺页主次校验 (eBPF <-> /proc, 本窗口):\n"
    "    eBPF raw(全部):   %10llu 次   (completed %llu, retry %llu)\n"
    "    /proc Δ(min+maj): %10llu 次   (已对账 %d 个进程)\n"
    "    一致性:           %s",
    au->raw, au->completed, au->retry,
    au->procflt_matched, au->matched_count,
    consist);
  if (au->matched_count > 0 &&
      (au->raw_matched || au->procflt_matched))
    fprintf(out, "  (偏差 %.0f%%)", dev_pct);
  fprintf(out,
    "\n"
    "    重试差(raw-comp): %10llu 次   (%.0f 次/s, 走 RETRY≈打到磁盘)\n\n",
    au->retry, retry_ps);
}

static void print_top_procs(FILE *out, struct proc_row *rows, int n,
                            double interval_s)
{
  int shown = 0;
  for (int i = 0; i < n; i++) {
    struct mem_proc_stats *s = &rows[i].st;
    if (s->fault_raw == 0 && s->direct_reclaim_cnt == 0) continue;
    shown++;
  }
  if (shown == 0) return;

  fprintf(out,
    "----------------------------------------------------------------------\n"
    "  TOP 进程 (按 major 增量 / 直接回收阻塞排序; 主次来自 /proc)\n"
    "----------------------------------------------------------------------\n\n");
  fprintf(out,
    "  %-7s %-16s %10s %10s %10s %8s %10s\n",
    "PID", "COMM", "minflt/s", "majflt/s", "retry/s", "回收次", "阻塞ms");

  int printed = 0;
  for (int i = 0; i < n && printed < MAX_TOP; i++) {
    struct mem_proc_stats *s = &rows[i].st;
    if (s->fault_raw == 0 && s->direct_reclaim_cnt == 0) continue;

    double retry_ps = sub_clamp(s->fault_raw, s->fault_completed) / interval_s;
    double reclaim_ms = (double)s->direct_reclaim_ns / 1e6;

    fprintf(out,
      "  %-7u %-16s %10.0f %10.0f %10.0f %8llu %10.2f\n",
      rows[i].tgid, rows[i].comm,
      (double)rows[i].minflt_d / interval_s,
      (double)rows[i].majflt_d / interval_s,
      retry_ps, s->direct_reclaim_cnt, reclaim_ms);
    printed++;
  }
  fprintf(out, "\n");
}

static void print_diagnosis(FILE *out, const struct meminfo *m,
                            const struct mem_sys_stats *sys,
                            const struct win_rates *r,
                            const struct flt_audit *au,
                            struct proc_row *rows, int nrow,
                            unsigned long long tot_reclaim_ns,
                            unsigned long long tot_reclaim_cnt,
                            double interval_s,
                            double avail_pct_lo, double majfault_hi)
{
  double avail_pct = pct(m->available, m->total);
  unsigned long long swap_used = sub_clamp(m->swaptotal, m->swapfree);
  double avg_stall_ms = tot_reclaim_cnt
    ? (double)tot_reclaim_ns / (double)tot_reclaim_cnt / 1e6 : 0.0;
  unsigned long long oom_win =
    sys->oom_kills > r->oom_delta ? sys->oom_kills : r->oom_delta;
  double retry_ps = au->retry / interval_s;

  int flag_lowmem  = avail_pct < avail_pct_lo && m->total > 0;
  int flag_major   = r->pgmajfault_ps > majfault_hi;
  int flag_swap    = (r->pswpin_ps > DEF_SWAPIN_HI || r->pswpout_ps > DEF_SWAPIN_HI)
                     && swap_used > 0;
  int flag_refault = r->refault_ps > DEF_REFAULT_HI;
  int flag_direct  = sys->direct_reclaim_cnt > 0 && avg_stall_ms > DIRECT_STALL_HI_MS;
  int flag_oom     = oom_win > 0;
  int flag_retry   = retry_ps > RETRY_HI_PS;
  int flag_fault   = r->pgfault_ps > FAULT_HI_PS;

  int triggers = flag_lowmem + flag_major + flag_swap + flag_refault +
                 flag_direct + flag_oom + flag_retry;

  fprintf(out,
    "----------------------------------------------------------------------\n"
    "  诊断结论\n"
    "----------------------------------------------------------------------\n\n");

  if (triggers == 0) {
    fprintf(out, "  (未检测到明显内存抖动 — 可用内存充足, 回收活动平稳)\n\n");
    fprintf(out, "======================================================================\n\n");
    fflush(out);
    return;
  }

  const char *anomaly_type, *root_cause;
  if (flag_oom) {
    anomaly_type = "内存耗尽 (OOM)";
    root_cause = "可用内存耗尽触发 OOM Killer, 进程被强制终止 — "
                 "内存申请已超出物理容量, 需扩容或定位泄漏进程";
  } else if (flag_swap && (flag_major || flag_lowmem)) {
    anomaly_type = "内存抖动 (换页颠簸)";
    root_cause = "匿名页规模超出物理内存, 频繁换入换出且 major fault 激增 — "
                 "业务进程持续申请大块内存导致回收压力上升";
  } else if (flag_refault && !flag_swap) {
    anomaly_type = "内存抖动 (缓存颠簸)";
    root_cause = "页缓存反复失效, 刚回收的页立即被重新读回 (refault 高) — "
                 "缓存与业务内存相互竞争";
  } else if (flag_direct && flag_lowmem) {
    anomaly_type = "内存抖动 (回收抖动)";
    root_cause = "可用内存不足触发直接回收, 业务进程在分配路径上同步回收并阻塞 — "
                 "回收速度跟不上分配速度";
  } else if (flag_major) {
    anomaly_type = "内存抖动 (缺页激增)";
    root_cause = "major fault 速率显著升高 — 映射文件/共享库被回收后反复触发缺页";
  } else if (flag_retry && flag_fault) {
    anomaly_type = "内存抖动 (缺页颠簸)";
    root_cause = "缺页速率与重试率双高, handle_mm_fault 大量返回 RETRY — "
                 "进程频繁触碰刚映射/刚换出的页, MM 锁竞争或 I/O 缺页密集";
  } else if (flag_retry) {
    anomaly_type = "内存抖动 (缺页重试)";
    root_cause = "缺页重试率偏高 — 部分缺页在等待磁盘 I/O 或争抢 mmap_lock, "
                 "虽未触发回收但已产生访问延迟";
  } else if (flag_lowmem) {
    anomaly_type = "内存高占用";
    root_cause = "可用内存持续偏低, 尚未出现明显回收抖动 — 需关注增长趋势";
  } else {
    anomaly_type = "内存异常波动";
    root_cause = "多因素综合, 建议结合 dmesg / OOM 日志进一步排查";
  }

  char assoc[128];
  if (flag_oom && sys->last_oom_pid) {
    char oom_comm[16];
    read_comm(sys->last_oom_pid, oom_comm, sizeof(oom_comm));
    snprintf(assoc, sizeof(assoc), "进程 %u (%s) — OOM 受害者",
             sys->last_oom_pid, oom_comm);
  } else if (nrow > 0 &&
             (rows[0].majflt_d > 0 || rows[0].st.direct_reclaim_cnt > 0)) {
    snprintf(assoc, sizeof(assoc), "进程 %u (%s)", rows[0].tgid, rows[0].comm);
  } else {
    snprintf(assoc, sizeof(assoc), "系统级 (无单一主导进程)");
  }

  fprintf(out,
    "  异常类型: %s\n"
    "  关联对象: %s\n"
    "  疑似根因: %s\n\n"
    "  关键指标:\n"
    "    可用内存:     %.1f%%  (阈值 %.0f%%, %s)\n"
    "    缺页速率:     %.0f 次/s  (阈值 %.0f, %s)\n"
    "    major fault:  %.0f 次/s  (阈值 %.0f, %s)\n"
    "    直接回收:     %llu 次, 平均阻塞 %.2f ms  %s\n"
    "    refault:      %.0f 页/s  %s\n"
    "    换入/换出:    %.0f / %.0f 页/s  %s\n"
    "    缺页重试差:   %.0f 次/s  %s   (raw-completed)\n"
    "    OOM:          %llu 次  %s\n\n",
    anomaly_type, assoc, root_cause,
    avail_pct, avail_pct_lo, flag_lowmem ? "!! 偏低" : "OK",
    r->pgfault_ps, FAULT_HI_PS, flag_fault ? "!! 偏高" : "OK",
    r->pgmajfault_ps, majfault_hi, flag_major ? "!! 超标" : "OK",
    sys->direct_reclaim_cnt, avg_stall_ms, flag_direct ? "!! 阻塞明显" : "",
    r->refault_ps, flag_refault ? "!! 偏高" : "",
    r->pswpin_ps, r->pswpout_ps, flag_swap ? "!! 换页活跃" : "",
    retry_ps, flag_retry ? "!! 偏高" : "",
    oom_win, flag_oom ? "!! 发生 OOM" : "");

  fprintf(out, "  证据:\n");
  int ev = 1;
  if (flag_oom) {
    char oom_comm[16] = "";
    if (sys->last_oom_pid)
      read_comm(sys->last_oom_pid, oom_comm, sizeof(oom_comm));
    fprintf(out, "    %d. 窗口内发生 %llu 次 OOM kill%s%s\n", ev++, oom_win,
            sys->last_oom_pid ? ", 最近受害者 " : "",
            sys->last_oom_pid ? oom_comm : "");
  }
  if (flag_lowmem)
    fprintf(out, "    %d. 可用内存降至 %.1f%%, 低于低水位 %.0f%%\n",
            ev++, avail_pct, avail_pct_lo);
  if (flag_major)
    fprintf(out, "    %d. major fault 速率 %.0f 次/s, 超出阈值 %.0f\n",
            ev++, r->pgmajfault_ps, majfault_hi);
  if (flag_swap)
    fprintf(out, "    %d. 换入 %.0f 页/s、换出 %.0f 页/s, Swap 正在活跃换页\n",
            ev++, r->pswpin_ps, r->pswpout_ps);
  if (flag_refault)
    fprintf(out, "    %d. refault %.0f 页/s, 刚回收的页被立即读回, 缓存严重不足\n",
            ev++, r->refault_ps);
  if (flag_direct)
    fprintf(out, "    %d. 触发直接回收 %llu 次, 进程分配路径平均阻塞 %.2f ms\n",
            ev++, sys->direct_reclaim_cnt, avg_stall_ms);
  if (flag_fault)
    fprintf(out, "    %d. 缺页速率 %.0f 次/s, 超出阈值 %.0f, 内存访问密集\n",
            ev++, r->pgfault_ps, FAULT_HI_PS);
  if (flag_retry) {
    double ratio = au->raw ? (double)au->retry / (double)au->raw * 100.0 : 0.0;
    fprintf(out, "    %d. 缺页重试差 %.0f 次/s (占全部缺页 %.0f%%), 大量缺页在等待磁盘或争抢锁\n",
            ev++, retry_ps, ratio);
  }
  if (nrow > 0 && rows[0].matched && rows[0].majflt_d > 0)
    fprintf(out, "    %d. 主导进程 %s(%u) major fault 最高: %.0f 次/s\n",
            ev++, rows[0].comm, rows[0].tgid,
            (double)rows[0].majflt_d / interval_s);

  fprintf(out, "\n======================================================================\n\n");
  fflush(out);
}


// ── 挂载辅助 ──────────────────────────────────────────────────────────

static struct bpf_link *links[8];
static int nlink;

static int attach_one(struct bpf_program *prog, const char *name)
{
  struct bpf_link *l = bpf_program__attach(prog);
  if (!l) {
    fprintf(stderr, "[!] 挂载 %s 失败 (该内核可能不支持, 已跳过)\n", name);
    return 0;
  }
  links[nlink++] = l;
  return 1;
}

static void detach_all(void)
{
  for (int i = 0; i < nlink; i++)
    bpf_link__destroy(links[i]);
  nlink = 0;
}


// 统一 JSON 报告
static void print_mem_json_report(const struct meminfo *m,
                                   const struct mem_sys_stats *sys,
                                   const struct win_rates *r,
                                   const struct flt_audit *au,
                                   struct proc_row *rows, int nrow,
                                   unsigned long long tot_reclaim_ns,
                                   unsigned long long tot_reclaim_cnt,
                                   double interval_s,
                                   double avail_pct_lo, double majfault_hi)
{
	const char *path = "report/mem.json";
	FILE *out = json_open(path);
	if (!out) return;

	char ts[32], buf[256];
	iso_timestamp(ts, sizeof(ts));
	struct sys_metrics sm;
	read_sys_metrics(&sm);

	double avail_pct = pct(m->available, m->total);
	unsigned long long swap_used = sub_clamp(m->swaptotal, m->swapfree);
	double swap_used_pct = pct(swap_used, m->swaptotal);
	double avg_stall_ms = tot_reclaim_cnt
		? (double)tot_reclaim_ns / (double)tot_reclaim_cnt / 1e6 : 0.0;
	unsigned long long oom_win =
		sys->oom_kills > r->oom_delta ? sys->oom_kills : r->oom_delta;
	double retry_ps = au->retry / interval_s;

	fprintf(out, "{\n");
	json_kv_str(out, 1, "module", "mem", 0);
	json_kv_str(out, 1, "timestamp", ts, 0);
	json_kv_double(out, 1, "duration_s", interval_s, "%.1f", 0);

	json_obj_begin(out, 1, "system");
	snprintf(buf, sizeof(buf), "%.1f GB", m->total / 1048576.0);
	json_kv_str(out, 2, "总内存", buf, 0);
	snprintf(buf, sizeof(buf), "%.1f GB (%.1f%%)", m->available / 1048576.0, avail_pct);
	json_kv_str(out, 2, "可用内存", buf, 0);
	snprintf(buf, sizeof(buf), "%.1f / %.1f GB (%.1f%%)",
		swap_used / 1048576.0, m->swaptotal / 1048576.0, swap_used_pct);
	json_kv_str(out, 2, "Swap", buf, 0);
	snprintf(buf, sizeof(buf), "%.2f / %.2f / %.2f", sm.load1, sm.load5, sm.load15);
	json_kv_str(out, 2, "系统负载 (1m/5m/15m)", buf, 1);
	json_obj_end(out, 1, 0);

	json_arr_begin(out, 1, "sections");

	// section: memory capacity kv
	{
		json_obj_begin_nokey(out, 2);
		json_kv_str(out, 3, "type", "kv", 0);
		json_kv_str(out, 3, "title", "内存容量快照", 0);
		json_arr_begin(out, 3, "rows");

		json_indent(out, 4);
		fprintf(out, "{\"key\": \"总内存\", \"value\": \"%.1f GB\"},\n",
			m->total / 1048576.0);
		json_indent(out, 4);
		fprintf(out, "{\"key\": \"可用内存\", \"value\": \"%.1f GB (%.1f%%)\"},\n",
			m->available / 1048576.0, avail_pct);
		json_indent(out, 4);
		fprintf(out, "{\"key\": \"空闲内存\", \"value\": \"%.1f GB\"},\n",
			m->free / 1048576.0);
		json_indent(out, 4);
		fprintf(out, "{\"key\": \"页缓存\", \"value\": \"%.1f GB\"},\n",
			m->cached / 1048576.0);
		json_indent(out, 4);
		fprintf(out, "{\"key\": \"匿名页\", \"value\": \"%.1f GB\"},\n",
			m->anon / 1048576.0);
		json_indent(out, 4);
		fprintf(out, "{\"key\": \"脏页/回写\", \"value\": \"%.1f / %.1f MB\"},\n",
			m->dirty / 1024.0, m->writeback / 1024.0);
		json_indent(out, 4);
		fprintf(out, "{\"key\": \"Swap 使用\", \"value\": \"%.1f / %.1f GB (%.1f%%)\"}\n",
			swap_used / 1048576.0, m->swaptotal / 1048576.0, swap_used_pct);

		json_arr_end(out, 3, 1);
		json_obj_end(out, 2, 0);
	}

	// section: page fault activity kv
	{
		json_obj_begin_nokey(out, 2);
		json_kv_str(out, 3, "type", "kv", 0);
		json_kv_str(out, 3, "title", "缺页与回收活动", 0);
		json_arr_begin(out, 3, "rows");

		json_indent(out, 4);
		fprintf(out, "{\"key\": \"缺页速率\", \"value\": \"%.0f 次/s\"},\n", r->pgfault_ps);
		json_indent(out, 4);
		fprintf(out, "{\"key\": \"major fault\", \"value\": \"%.0f 次/s\"},\n", r->pgmajfault_ps);
		json_indent(out, 4);
		fprintf(out, "{\"key\": \"换入 pswpin\", \"value\": \"%.0f 页/s\"},\n", r->pswpin_ps);
		json_indent(out, 4);
		fprintf(out, "{\"key\": \"换出 pswpout\", \"value\": \"%.0f 页/s\"},\n", r->pswpout_ps);
		json_indent(out, 4);
		fprintf(out, "{\"key\": \"refault\", \"value\": \"%.0f 页/s\"},\n", r->refault_ps);
		json_indent(out, 4);
		fprintf(out, "{\"key\": \"kswapd 唤醒\", \"value\": \"%llu 次\"},\n", sys->kswapd_wake_count);
		json_indent(out, 4);
		fprintf(out, "{\"key\": \"直接回收\", \"value\": \"%llu 次 (阻塞 %.2f ms)\"},\n",
			sys->direct_reclaim_cnt, avg_stall_ms);
		json_indent(out, 4);
		fprintf(out, "{\"key\": \"回收扫描/回收\", \"value\": \"%llu / %llu 页\"},\n",
			sys->page_scan, sys->page_steal);
		json_indent(out, 4);
		fprintf(out, "{\"key\": \"OOM 杀进程\", \"value\": \"%llu 次\"},\n", sys->oom_kills);
		json_indent(out, 4);
		fprintf(out, "{\"key\": \"缺页重试差\", \"value\": \"%llu 次 (%.0f 次/s)\"}\n",
			au->retry, retry_ps);

		json_arr_end(out, 3, 1);
		json_obj_end(out, 2, 0);
	}

	// section: top processes table
	{
		json_obj_begin_nokey(out, 2);
		json_kv_str(out, 3, "type", "table", 0);
		json_kv_str(out, 3, "title", "TOP 缺页进程", 0);
		fprintf(out, "          \"columns\": [\"PID\", \"进程\", \"minflt/s\", \"majflt/s\", \"retry/s\", \"回收次\", \"阻塞ms\"],\n");
		json_arr_begin(out, 3, "rows");

		int printed = 0;
		for (int i = 0; i < nrow && printed < 5; i++) {
			struct mem_proc_stats *s = &rows[i].st;
			if (s->fault_raw == 0 && s->direct_reclaim_cnt == 0) continue;

			double rps = sub_clamp(s->fault_raw, s->fault_completed) / interval_s;
			double rms = (double)s->direct_reclaim_ns / 1e6;

			if (printed > 0) fprintf(out, ",\n");
			json_indent(out, 4);
			fprintf(out, "[\"%u\", \"%s\", \"%.0f\", \"%.0f\", \"%.0f\", \"%llu\", \"%.2f\"]",
				rows[i].tgid, rows[i].comm,
				(double)rows[i].minflt_d / interval_s,
				(double)rows[i].majflt_d / interval_s,
				rps, s->direct_reclaim_cnt, rms);
			printed++;
		}
		fprintf(out, "\n");
		json_arr_end(out, 3, 1);
		json_obj_end(out, 2, 0);
	}

	// section: diagnosis
	{
		int flag_lowmem  = avail_pct < avail_pct_lo && m->total > 0;
		int flag_major   = r->pgmajfault_ps > majfault_hi;
		int flag_swap    = (r->pswpin_ps > DEF_SWAPIN_HI || r->pswpout_ps > DEF_SWAPIN_HI)
		                   && swap_used > 0;
		int flag_refault = r->refault_ps > DEF_REFAULT_HI;
		int flag_direct  = sys->direct_reclaim_cnt > 0 && avg_stall_ms > DIRECT_STALL_HI_MS;
		int flag_oom     = oom_win > 0;
		int flag_retry   = retry_ps > RETRY_HI_PS;
		int flag_fault   = r->pgfault_ps > FAULT_HI_PS;

		int triggers = flag_lowmem + flag_major + flag_swap + flag_refault +
		               flag_direct + flag_oom + flag_retry;

		json_obj_begin_nokey(out, 2);
		json_kv_str(out, 3, "type", "diagnosis", 0);
		json_kv_str(out, 3, "title", "诊断结论", 0);
		fprintf(out, "          \"findings\": [\n");

		if (triggers == 0) {
			fprintf(out, "            {\"target\": \"系统内存\", \"is_anomaly\": false, "
				"\"subtype\": \"正常\", "
				"\"root_cause\": \"未检测到明显内存抖动\", "
				"\"suggestion\": \"系统内存状态正常\"}\n");
		} else {
			const char *anomaly_type, *root_cause;
			if (flag_oom) {
				anomaly_type = "内存耗尽 (OOM)";
				root_cause = "可用内存耗尽触发 OOM Killer, 进程被强制终止 — 内存申请已超出物理容量, 需扩容或定位泄漏进程";
			} else if (flag_swap && (flag_major || flag_lowmem)) {
				anomaly_type = "内存抖动 (换页颠簸)";
				root_cause = "匿名页规模超出物理内存, 频繁换入换出且 major fault 激增 — 业务进程持续申请大块内存导致回收压力上升";
			} else if (flag_refault && !flag_swap) {
				anomaly_type = "内存抖动 (缓存颠簸)";
				root_cause = "页缓存反复失效, 刚回收的页立即被重新读回 (refault 高) — 缓存与业务内存相互竞争";
			} else if (flag_direct && flag_lowmem) {
				anomaly_type = "内存抖动 (回收抖动)";
				root_cause = "可用内存不足触发直接回收, 业务进程在分配路径上同步回收并阻塞 — 回收速度跟不上分配速度";
			} else if (flag_major) {
				anomaly_type = "内存抖动 (缺页激增)";
				root_cause = "major fault 速率显著升高 — 映射文件/共享库被回收后反复触发缺页";
			} else if (flag_retry && flag_fault) {
				anomaly_type = "内存抖动 (缺页颠簸)";
				root_cause = "缺页速率与重试率双高, handle_mm_fault 大量返回 RETRY — 进程频繁触碰刚映射/刚换出的页, MM 锁竞争或 I/O 缺页密集";
			} else if (flag_retry) {
				anomaly_type = "内存抖动 (缺页重试)";
				root_cause = "缺页重试率偏高 — 部分缺页在等待磁盘 I/O 或争抢 mmap_lock, 虽未触发回收但已产生访问延迟";
			} else if (flag_lowmem) {
				anomaly_type = "内存高占用";
				root_cause = "可用内存持续偏低, 尚未出现明显回收抖动 — 需关注增长趋势";
			} else {
				anomaly_type = "内存异常波动";
				root_cause = "多因素综合, 建议结合 dmesg / OOM 日志进一步排查";
			}

			// 关联对象
			char assoc[128];
			if (flag_oom && sys->last_oom_pid) {
				char oom_comm[16];
				read_comm(sys->last_oom_pid, oom_comm, sizeof(oom_comm));
				snprintf(assoc, sizeof(assoc), "进程 %u (%s) — OOM 受害者",
					sys->last_oom_pid, oom_comm);
			} else if (nrow > 0 &&
			           (rows[0].majflt_d > 0 || rows[0].st.direct_reclaim_cnt > 0)) {
				snprintf(assoc, sizeof(assoc), "进程 %u (%s)", rows[0].tgid, rows[0].comm);
			} else {
				snprintf(assoc, sizeof(assoc), "系统级 (无单一主导进程)");
			}

			fprintf(out, "            {\n");
			fprintf(out, "              \"target\": \"%s\",\n", assoc);
			fprintf(out, "              \"is_anomaly\": true,\n");
			fprintf(out, "              \"subtype\": \"%s\",\n", anomaly_type);
			fprintf(out, "              \"root_cause\": \"%s\",\n", root_cause);
			fprintf(out, "              \"suggestion\": \"结合 dmesg/OOM 日志进一步排查，关注 top 进程内存增长趋势\",\n");

			fprintf(out, "              \"key_metrics\": {\n");
			fprintf(out, "                \"可用内存\": \"%.1f%% (阈值 %.0f%%, %s)\",\n",
				avail_pct, avail_pct_lo, flag_lowmem ? "!! 偏低" : "OK");
			fprintf(out, "                \"缺页速率\": \"%.0f 次/s (阈值 %.0f, %s)\",\n",
				r->pgfault_ps, FAULT_HI_PS, flag_fault ? "!! 偏高" : "OK");
			fprintf(out, "                \"major fault\": \"%.0f 次/s (阈值 %.0f, %s)\",\n",
				r->pgmajfault_ps, majfault_hi, flag_major ? "!! 超标" : "OK");
			fprintf(out, "                \"直接回收\": \"%llu 次 (阻塞 %.2f ms)%s\",\n",
				sys->direct_reclaim_cnt, avg_stall_ms, flag_direct ? " !! 阻塞明显" : "");
			fprintf(out, "                \"refault\": \"%.0f 页/s%s\",\n",
				r->refault_ps, flag_refault ? " !! 偏高" : "");
			fprintf(out, "                \"换入/换出\": \"%.0f / %.0f 页/s%s\",\n",
				r->pswpin_ps, r->pswpout_ps, flag_swap ? " !! 换页活跃" : "");
			fprintf(out, "                \"缺页重试差\": \"%.0f 次/s%s\",\n",
				retry_ps, flag_retry ? " !! 偏高" : "");
			fprintf(out, "                \"OOM\": \"%llu 次%s\"\n",
				oom_win, flag_oom ? " !! 发生 OOM" : "");
			fprintf(out, "              },\n");

			fprintf(out, "              \"evidence\": [\n");
			int ev = 0;
			if (flag_oom) {
				if (ev > 0) fprintf(out, ",\n");
				char oom_comm[16] = "";
				if (sys->last_oom_pid) read_comm(sys->last_oom_pid, oom_comm, sizeof(oom_comm));
				fprintf(out, "                \"窗口内发生 %llu 次 OOM kill%s%s\"",
					oom_win, sys->last_oom_pid ? ", 受害者 " : "",
					sys->last_oom_pid ? oom_comm : "");
				ev++;
			}
			if (flag_lowmem) {
				if (ev > 0) fprintf(out, ",\n");
				fprintf(out, "                \"可用内存降至 %.1f%%, 低于低水位 %.0f%%\"", avail_pct, avail_pct_lo);
				ev++;
			}
			if (flag_major) {
				if (ev > 0) fprintf(out, ",\n");
				fprintf(out, "                \"major fault %.0f 次/s, 超出阈值 %.0f\"", r->pgmajfault_ps, majfault_hi);
				ev++;
			}
			if (flag_swap) {
				if (ev > 0) fprintf(out, ",\n");
				fprintf(out, "                \"换入 %.0f 页/s、换出 %.0f 页/s, Swap 正在活跃换页\"", r->pswpin_ps, r->pswpout_ps);
				ev++;
			}
			if (flag_refault) {
				if (ev > 0) fprintf(out, ",\n");
				fprintf(out, "                \"refault %.0f 页/s, 刚回收的页被立即读回, 缓存严重不足\"", r->refault_ps);
				ev++;
			}
			if (flag_direct) {
				if (ev > 0) fprintf(out, ",\n");
				fprintf(out, "                \"触发直接回收 %llu 次, 进程分配路径平均阻塞 %.2f ms\"", sys->direct_reclaim_cnt, avg_stall_ms);
				ev++;
			}
			if (flag_fault) {
				if (ev > 0) fprintf(out, ",\n");
				fprintf(out, "                \"缺页速率 %.0f 次/s, 超出阈值 %.0f, 内存访问密集\"", r->pgfault_ps, FAULT_HI_PS);
				ev++;
			}
			if (flag_retry) {
				if (ev > 0) fprintf(out, ",\n");
				double ratio = au->raw ? (double)au->retry / (double)au->raw * 100.0 : 0.0;
				fprintf(out, "                \"缺页重试差 %.0f 次/s (占全部缺页 %.0f%%), 大量缺页在等待磁盘或争抢锁\"", retry_ps, ratio);
				ev++;
			}
			if (nrow > 0 && rows[0].matched && rows[0].majflt_d > 0) {
				if (ev > 0) fprintf(out, ",\n");
				fprintf(out, "                \"主导进程 %s(%u) major fault 最高: %.0f 次/s\"",
					rows[0].comm, rows[0].tgid,
					(double)rows[0].majflt_d / interval_s);
				ev++;
			}
			fprintf(out, "\n              ]\n");
			fprintf(out, "            }\n");
		}

		fprintf(out, "          ]\n");
		json_obj_end(out, 2, 1);
	}

	json_arr_end(out, 1, 1);
	fprintf(out, "}\n");
	json_close(out);
}

static void usage(const char *prog)
{
  fprintf(stderr,
    "用法: %s [选项]\n"
    "\n"
    "内存抖动观测工具 — eBPF 按进程探测缺页洪流(raw/completed)与直接回收、\n"
    "kswapd、OOM 等信号; /proc/<pid>/stat 提供权威 major/minor 增量并与 eBPF 对账;\n"
    "/proc/meminfo 与 /proc/vmstat 提供容量快照与系统级速率。\n"
    "\n"
    "选项:\n"
    "  -i, --interval <秒>            采样间隔（默认: %d）\n"
    "  -d, --duration <秒>            总运行时长, 0 表示持续运行（默认: 0）\n"
    "  -a, --avail-threshold <百分比> 可用内存低水位阈值（默认: %.0f）\n"
    "  -f, --majfault-threshold <次/s> major fault 速率阈值（默认: %.0f）\n"
    "  -h, --help                     显示本帮助信息\n"
    "\n"
    "示例:\n"
    "  sudo %s                 # 默认参数运行\n"
    "  sudo %s -i 5 -d 60      # 每 5 秒采样, 运行 60 秒\n"
    "  sudo %s -a 15 -f 100    # 更敏感的阈值\n",
    prog, DEFAULT_INTERVAL, DEF_AVAIL_PCT_LO, DEF_MAJFAULT_HI,
    prog, prog, prog);
}

int run_mem(int argc, char **argv)
{
  int interval = DEFAULT_INTERVAL;
  int duration = 0;
  double avail_pct_lo = DEF_AVAIL_PCT_LO;
  double majfault_hi  = DEF_MAJFAULT_HI;

  static struct option long_opts[] = {
    {"interval",           required_argument, 0, 'i'},
    {"duration",           required_argument, 0, 'd'},
    {"avail-threshold",    required_argument, 0, 'a'},
    {"majfault-threshold", required_argument, 0, 'f'},
    {"help",               no_argument,       0, 'h'},
    {0, 0, 0, 0}
  };

  int opt;
  while ((opt = getopt_long(argc, argv, "i:d:a:f:h", long_opts, NULL)) != -1) {
    switch (opt) {
    case 'i': interval = atoi(optarg); break;
    case 'd': duration = atoi(optarg); break;
    case 'a': avail_pct_lo = atof(optarg); break;
    case 'f': majfault_hi = atof(optarg); break;
    case 'h': usage(argv[0]); return 0;
    default:  usage(argv[0]); return 1;
    }
  }

  if (check_interval(interval) != 0)
    return 1;

  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);

  struct mem_anomaly_bpf *skel = mem_anomaly_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "无法加载 BPF 程序（需要 root 权限）\n");
    return 1;
  }

  attach_one(skel->progs.mm_fault_exit,           "kretprobe/handle_mm_fault");
  attach_one(skel->progs.on_kswapd_wake,          "mm_vmscan_kswapd_wake");
  attach_one(skel->progs.on_direct_reclaim_begin, "mm_vmscan_direct_reclaim_begin");
  attach_one(skel->progs.on_direct_reclaim_end,   "mm_vmscan_direct_reclaim_end");
  attach_one(skel->progs.on_lru_shrink_inactive,  "mm_vmscan_lru_shrink_inactive");
  attach_one(skel->progs.on_oom_mark_victim,      "oom/mark_victim");

  if (nlink == 0) {
    fprintf(stderr, "所有探针均挂载失败, 退出\n");
    mem_anomaly_bpf__destroy(skel);
    return 1;
  }

  int proc_fd    = bpf_map__fd(skel->maps.pid_mem);
  int sys_fd     = bpf_map__fd(skel->maps.global_mem);
  if (proc_fd < 0 || sys_fd < 0) {
    fprintf(stderr, "无法获取 BPF map fd\n");
    detach_all();
    mem_anomaly_bpf__destroy(skel);
    return 1;
  }

  fprintf(stderr, "[*] 内存抖动观测已启动, 采样间隔=%ds (成功挂载 %d 个探针)\n",
          interval, nlink);

  struct vmstat prev;
  struct mem_sys_stats prev_sys;
  read_vmstat(&prev);
  read_sys_stats(sys_fd, &prev_sys);
  time_t start = time(NULL);

  while (!exiting) {
    sleep(interval);

    struct meminfo m;
    struct vmstat now;
    struct win_rates rates;
    struct mem_sys_stats sys;
    struct proc_row rows[MAX_ROWS];
    struct flt_audit au;

    read_meminfo(&m);
    read_vmstat(&now);
    compute_rates(&now, &prev, (double)interval, &rates);
    prev = now;

    // BPF sys 累积值 → 窗口增量
    read_sys_stats(sys_fd, &sys);
    struct mem_sys_stats sys_delta;
    sys_delta.kswapd_wake_count   = sub_clamp(sys.kswapd_wake_count,   prev_sys.kswapd_wake_count);
    sys_delta.kswapd_active_ns    = sub_clamp(sys.kswapd_active_ns,    prev_sys.kswapd_active_ns);
    sys_delta.direct_reclaim_cnt  = sub_clamp(sys.direct_reclaim_cnt,  prev_sys.direct_reclaim_cnt);
    sys_delta.direct_reclaim_ns   = sub_clamp(sys.direct_reclaim_ns,   prev_sys.direct_reclaim_ns);
    sys_delta.reclaimed_pages     = sub_clamp(sys.reclaimed_pages,     prev_sys.reclaimed_pages);
    sys_delta.page_scan           = sub_clamp(sys.page_scan,           prev_sys.page_scan);
    sys_delta.page_steal          = sub_clamp(sys.page_steal,          prev_sys.page_steal);
    sys_delta.oom_kills           = sub_clamp(sys.oom_kills,           prev_sys.oom_kills);
    sys_delta.last_oom_pid        = sys.last_oom_pid;
    prev_sys = sys;

    g_gen++;
    int nrow = read_proc_rows(proc_fd, rows, MAX_ROWS);
    enrich_and_audit(rows, nrow, &au);
    if (nrow > 1) qsort(rows, nrow, sizeof(rows[0]), cmp_proc);
    flt_cache_gc();

    unsigned long long tot_reclaim_ns = 0, tot_reclaim_cnt = 0;
    for (int i = 0; i < nrow; i++) {
      tot_reclaim_ns += rows[i].st.direct_reclaim_ns;
      tot_reclaim_cnt += rows[i].st.direct_reclaim_cnt;
    }

    print_overview(stdout, &m, &sys_delta, &rates, &au,
                   tot_reclaim_ns, tot_reclaim_cnt, (double)interval);
    print_top_procs(stdout, rows, nrow, (double)interval);
    print_diagnosis(stdout, &m, &sys_delta, &rates, &au, rows, nrow,
                    tot_reclaim_ns, tot_reclaim_cnt, (double)interval,
                    avail_pct_lo, majfault_hi);

	if (exiting || (duration > 0 && time(NULL) - start >= duration)) {
		print_mem_json_report(&m, &sys_delta, &rates, &au, rows, nrow,
				  tot_reclaim_ns, tot_reclaim_cnt, (double)interval,
				  avail_pct_lo, majfault_hi);
		json_to_markdown("report/mem.json", "report/mem.md");
		break;
	}
  }

  fprintf(stderr, "[*] 正在退出...\n");
  detach_all();
  mem_anomaly_bpf__destroy(skel);
  return 0;
}
