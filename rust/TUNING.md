# s3gateway-rs — Tuning & Operations Guide

Audience: an SRE bringing `s3gateway-rs` up on the target box (12-core Xeon Silver
4310, ConnectX-7 80 Gbps NIC, encrypted ZFS RaidZ3 on 24 NVMe). This guide is
about getting close to line rate without chasing wins that don't exist.

---

## 1. The honest performance model

This gateway's job is to add **as little CPU as possible on top of ZFS**.

On encrypted ZFS RaidZ3, the dominant per-byte CPU cost lives **in the kernel,
inside ZFS, and is irreducible by any gateway** regardless of the language it's
written in:

- **Native AES encryption** of every block (ZFS dataset-level encryption).
- **fletcher4 checksums** computed over every block on both read and write.
- **RaidZ3 triple-parity** generation on write (and reconstruction on degraded
  read).

These run in ZFS's ZIO taskqs (`z_wr_iss`, `z_wr_int`, `z_rd_int`, etc.) on every
byte that crosses the pool, no matter what the gateway does. A rewrite — Go to
Rust or otherwise — can only remove work that happens **outside** ZFS:

1. **TLS crypto** — moved off the CPU entirely via kTLS NIC offload.
2. **Userspace copies** — removed via Direct IO (no ARC→userspace bounce on read).
3. **Task switching / cache churn** — minimized via thread-per-core shared-nothing.

Set expectations accordingly. If the box is bottlenecked on ZFS AES + parity +
checksum, the gateway is already out of the way and the levers below buy bounded
amounts. If it's bottlenecked on userspace TLS or copies, the levers buy a lot.
**Profile before you tune.**

---

## 2. Profile FIRST

The first question is always: **where is the CPU — userspace (`us`) or kernel
(`sy`), and which kernel threads?**

```bash
# Per-core split of us / sy / si (softirq) / id, live
mpstat -P ALL 1

# Where is on-CPU time going, system-wide (kernel + user symbols)
sudo perf top

# Record a flame graph during a sustained transfer
sudo perf record -F 99 -a -g -- sleep 30
sudo perf script | stackcollapse-perf.pl | flamegraph.pl > fg.svg

# Watch the ZFS ZIO taskq threads specifically
top -H -p "$(pgrep -d, -f 'z_wr_iss|z_rd_int|z_wr_int|z_null')"
# or just scan them:
ps -eLf | grep -E 'z_wr_iss|z_wr_int|z_rd_int|z_ioctl|z_null'
```

**Decision rule:**

- CPU dominated by ZFS kernel taskqs (`z_wr_iss`, `z_rd_int`, AES/fletcher
  symbols in `perf top`) → you're near the irreducible floor. kTLS and Direct IO
  help bounded amounts; ZFS tuning (section 3) is the main remaining lever.
- CPU dominated by userspace TLS symbols (rustls / AES-GCM in the gateway
  process) → **kTLS is the big win.** Get offload working (section 4) first.
- High `%si` (softirq) concentrated on a few cores → NIC IRQs aren't spread; fix
  RSS / IRQ affinity (section 5).

---

## 3. ZFS tuning (prioritized)

Apply to the dataset backing `--data-dir` (shown as `<ds>`). Each setting has a
specific reason; don't cargo-cult them onto unrelated datasets.

```bash
# 1) Compression OFF — S3 payloads are already compressed (media, archives,
#    encrypted blobs). Compression burns CPU for ~0 ratio and adds a per-block
#    pass on the hot path.
zfs set compression=off <ds>

# 2) Cache only metadata — streaming large objects once would evict the entire
#    ARC for data that's never re-read. Keep the ARC for metadata + listings
#    (HEAD/LIST stay fast); let bulk data stream past it.
zfs set primarycache=metadata <ds>

# 3) Large records — fewer, bigger ZIO ops mean fewer checksum/parity/AES
#    invocations per MB and better AES-GCM batching per block.
zfs set recordsize=1M <ds>

# 4) No atime — kill a metadata write on every read.
zfs set atime=off <ds>

# 5) OpenZFS 2.3 Direct IO — let O_DIRECT reads/writes bypass the ARC copy.
#    Pair with the gateway's O_DIRECT path (page-aligned buffers, on by default).
zfs set direct=standard <ds>
```

**Pool-level (set at creation):**

- `ashift=12` (4K sectors) — or `ashift=13` (8K) if the NVMe reports an 8K
  physical/optimal block. Wrong ashift causes read-modify-write amplification.
- A **mirrored NVMe `special` vdev** for metadata + small blocks. This pulls the
  metadata and small-file IO that drives LIST/HEAD off the RaidZ3 data vdevs and
  onto a fast mirror, which is exactly where listing latency comes from.

  ```bash
  # at pool create, or:
  zpool add <pool> special mirror /dev/nvmeXn1 /dev/nvmeYn1
  # optionally route small blocks to it:
  zfs set special_small_blocks=64K <ds>
  ```

### Why each, briefly

| Setting                    | Why                                                                 |
| -------------------------- | ------------------------------------------------------------------- |
| `compression=off`          | Pre-compressed payloads → CPU spent for no space saving.            |
| `primarycache=metadata`    | Streaming reads would thrash the ARC; cache only what's re-read.    |
| `recordsize=1M`            | Fewer/larger ZIO ops → less per-block AES/checksum/parity overhead. |
| `atime=off`                | Removes a metadata write per read.                                  |
| `direct=standard`          | Removes the ARC→socket memcpy on the read path.                     |
| `ashift=12/13`             | Match device block size; avoid read-modify-write amplification.     |
| `special` vdev             | Accelerates metadata-heavy LIST/HEAD; offloads small files.         |

### The zero-copy caveat (important)

ZFS serves data from the **ARC**, not the page cache. That means `sendfile`,
`splice`, and `mmap` are **not zero-copy on ZFS** — there is no page-cache page to
hand to the socket, so the kernel copies out of the ARC anyway. Do **not** expect
a sendfile-style path to beat a plain buffered write on ZFS.

Even with `O_DIRECT`, the data still goes through the ZIO pipeline: O_DIRECT can
skip the ARC copy, but it **cannot bypass the crypto / checksum / parity
transform** — those are intrinsic to writing a block to an encrypted RaidZ3 pool.

This is exactly why the gateway targets **one CPU touch + offloaded TLS**, not
zero-touch: the one unavoidable userspace pass (the one-pass MD5 for the ETag) is
folded into the same loop that streams the bytes, and TLS — the only other
per-byte CPU cost the gateway controls — is pushed to the NIC.

---

## 4. kTLS / ConnectX-7 offload bring-up & verification

### Bring-up

```bash
# Load the kernel TLS modules
sudo modprobe tls
sudo modprobe tls_device

# Enable HW TLS offload on the PHYSICAL mlx5 interface
sudo ethtool -K <iface> tls-hw-tx-offload on tls-hw-rx-offload on

# Confirm capability + state
ethtool -k <iface> | grep tls
```

Then run the gateway with TLS and kTLS enabled:

```bash
./s3gateway-rs --data-dir /srv/s3data --credentials credentials.json \
  --port 8443 --tls-cert fullchain.pem --tls-key privkey.pem --ktls true
```

### Cipher / version constraints

- **AES-GCM-128 / AES-GCM-256 only** — these are the offloadable suites.
- **TLS 1.2** is always offloadable on the ConnectX-7.
- **TLS 1.3** hardware offload requires a recent kernel (offload support merged
  upstream in 2025). On older kernels, fall back to **TLS 1.2 AES-GCM** rather
  than running TLS 1.3 in software.

### Verify it's actually offloading

A handshake succeeding tells you nothing about offload. Watch the NIC counters
under real load:

```bash
watch -n1 'ethtool -S <iface> | grep -E \
  "tx_tls_encrypted_bytes|tx_tls_ctx|rx_tls_decrypted_bytes|tx_tls_ooo|tx_tls_drop"'
```

Interpretation:

- `tx_tls_ctx` **rising** → hardware TLS contexts are being installed (offload
  engaged for new connections).
- `tx_tls_encrypted_bytes` / `rx_tls_decrypted_bytes` **climbing under load** →
  the NIC crypto engine is live and doing the bulk work.
- `tx_tls_ooo` (out-of-order) and `*_drop` **rising** → packets are falling back
  to software re-encryption. Some churn is normal; sustained growth means offload
  is thrashing — investigate reordering, RX-offload fragility, or a bad path.

### Operational notes

- **RX offload is fragile.** It resyncs on packet loss/reorder and **does not work
  over bonds, `veth`, or tunnels.** Bind the listener to the physical mlx5
  interface. TX offload is the more robust and higher-value half.
- **The handshake stays on the CPU** (asymmetric crypto, cert verification). This
  is negligible relative to bulk transfer — don't try to offload it.
- **Keep software fallback on** (`--ktls true` already does this: rustls handles
  any connection the NIC can't). Never run with no software path.

---

## 5. Thread-per-core / OS tuning

- **`--workers` = physical core count.** On the 12-core box that's `--workers 12`.
  If you dedicate one core to NIC interrupt handling (see IRQ affinity below),
  use `--workers 11` and pin IRQs to the spare core.
- **Core pinning** is automatic: each worker is a current-thread tokio runtime
  pinned to a core via `core_affinity`, each with its own `SO_REUSEPORT` listener.
  The kernel spreads accepted connections across the per-core listeners; a
  connection stays on one core for its lifetime.
- **IRQ affinity / RSS.** Spread the mlx5 receive queues across cores so softirq
  load (TLS RX, packet processing) doesn't pile onto one core:

  ```bash
  # Match RX queue count to cores, then spread IRQs
  ethtool -L <iface> combined 12
  # NVIDIA ships set_irq_affinity.sh with the mlx driver:
  sudo set_irq_affinity.sh <iface>
  ```

  Align RSS/queue placement with the worker cores so a connection's RX softirq and
  its serving runtime land on the same core where possible.
- **NUMA:** single socket on this box — there is no remote-memory concern, so no
  `numactl` pinning is required. (Document the topology if the box is ever
  upgraded to dual-socket; then per-core runtimes must respect NUMA locality.)
- **Hugepages:** optional. They reduce TLB pressure for large resident sets but
  are not required; only revisit if `perf` shows significant `dTLB` miss cost.

---

## 6. Benchmarking procedure

Measure the storage floor first, then the gateway, then under TLS.

### Baseline (storage floor, no gateway)

```bash
# Sequential write floor to the pool (bypass cache, large blocks)
dd if=/dev/zero of=/srv/s3data/zz.bin bs=1M count=10240 oflag=direct status=progress
# Sequential read floor (drop ARC first if you want a cold number)
dd if=/srv/s3data/zz.bin of=/dev/null bs=1M iflag=direct status=progress
```

This is the ceiling the gateway can't exceed — if `dd` can't hit line rate, the
gateway won't either, and the bottleneck is ZFS/NVMe, not the gateway.

### Large-object throughput (both directions)

```bash
# 10 GB object, upload then download, timed
truncate -s 10G /tmp/10g.bin
time aws --endpoint-url https://host:8443 s3 cp /tmp/10g.bin s3://bench/10g.bin
time aws --endpoint-url https://host:8443 s3 cp s3://bench/10g.bin /tmp/out.bin
```

### Concurrency sweep

Run N parallel `aws s3 cp` transfers (N = 1, 2, 4, 8, 12, 24) and record
aggregate throughput at each step. Throughput should rise with concurrency until
a resource saturates — note which one does.

### What to watch during a run

| Signal              | Tool                                              | What it tells you                          |
| ------------------- | ------------------------------------------------- | ------------------------------------------ |
| Wire throughput     | `ethtool -S <iface>` deltas, `sar -n DEV 1`       | Are you approaching 80 Gbps?               |
| Per-core `%us`/`%sy`| `mpstat -P ALL 1`                                 | User vs kernel split; hot/idle cores       |
| ZFS / ARC behavior  | `arcstat 1`, `zpool iostat -v 1`                  | ARC hit/miss, per-vdev IO, parity load     |
| kTLS offload        | `ethtool -S <iface> \| grep tls`                  | Is the NIC doing crypto (section 4)?        |
| ZIO taskqs          | `top -H` / `perf top`                             | Are ZFS kernel threads the bottleneck?     |

### Headline target and the likely gating factor

The headline target is **80 Gbps line rate**. With kTLS engaged and Direct IO on,
the gateway should be a thin layer; the gating factor will most likely be **ZFS
crypto + RaidZ3 parity + fletcher4** saturating CPU in the ZIO taskqs — i.e. the
irreducible floor from section 1, not the gateway. If `perf` says otherwise (TLS
in userspace, copies, lock contention in the process), that's a gateway/config
problem worth chasing; if it says ZFS taskqs, you're done — scale cores or relax
RaidZ3 to RaidZ2/mirrors if the throughput need outranks the parity guarantee.
