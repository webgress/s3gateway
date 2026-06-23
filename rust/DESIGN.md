# s3gateway-rs — Design Rationale

Engineer-to-engineer notes on why this gateway is built the way it is. It is a
performance-focused reimplementation of the Go gateway in the repo root, targeting
one machine: 12-core Xeon Silver 4310, ConnectX-7 80 Gbps NIC (kTLS-capable),
encrypted ZFS RaidZ3 on 24 NVMe.

## The starting question: what can a rewrite actually remove?

We began by asking where per-byte CPU goes on the target box, because that bounds
everything a rewrite can buy. On encrypted ZFS RaidZ3, the dominant cost is
**in-kernel and irreducible by any gateway**: native AES dataset encryption,
fletcher4 checksums, and RaidZ3 triple-parity generation. These run in the ZFS
ZIO taskqs on every byte regardless of the gateway's language or architecture.

So the gateway can only remove work *outside* ZFS:

1. **TLS crypto** — the one large per-byte CPU cost we control.
2. **Userspace copies** — the ARC→userspace bounce on reads.
3. **Task-switching / cache churn** — overhead from a work-stealing, shared runtime.

Every architectural decision below follows from this scoping conclusion: spend
engineering only where the work is actually removable.

## Thread-per-core, shared-nothing

A shared multi-threaded runtime (work-stealing scheduler, connections migrating
between threads) pays for it in cache-line bouncing, cross-core synchronization,
and task-switch overhead — all pure waste at high connection/throughput counts. We
run **one pinned current-thread tokio runtime per core**, each with its own
`SO_REUSEPORT` listener. The kernel load-balances accepts; a connection lives and
dies on one core. No work-stealing, no cross-core locks on the hot path, warm
per-core caches. On a single-socket box there's no NUMA wrinkle to complicate it.

## kTLS is the centerpiece

TLS bulk crypto is the single biggest per-byte cost a gateway can legitimately
eliminate, and the ConnectX-7 can do it inline. We terminate the handshake in
userspace with rustls, then hand the established session to the kernel TLS stack
(the `ktls` crate) so AES-GCM record crypto runs **on the NIC**, off the CPU
entirely. The handshake stays on-CPU but is negligible against bulk transfer.
Software fallback (plain rustls) is always available for connections the NIC
can't offload, so correctness never depends on the offload path. This is the
decision the whole architecture is built to enable.

## Direct-IO blocking storage pool (not io_uring)

ZFS has **no async IO path** — there is no io_uring fast path through the ZIO
pipeline; a submitted IO still lands in ZFS's synchronous-from-the-caller's-view
machinery. So an async storage API would be a thin wrapper over blocking calls
anyway. We therefore use a **blocking Direct-IO pool**: `O_DIRECT` with
page-aligned buffers via `pread`/`pwrite`, driven from `spawn_blocking`. Direct IO
removes the ARC→userspace memcpy on reads. It cannot bypass the crypto / checksum
/ parity transform (that's intrinsic to an encrypted RaidZ3 write), and because
ZFS serves from the ARC rather than the page cache, `sendfile`/`splice`/`mmap` are
not zero-copy here — so we don't chase zero-copy. The target is exactly **one CPU
touch + offloaded TLS**, not zero-touch. `O_DIRECT` falls back to buffered IO
transparently on filesystems that reject it (tmpfs, overlayfs, alignment EINVAL).

## tokio thread-per-core over compio / io_uring runtimes

Given storage is blocking on ZFS anyway, io_uring's headline win — syscall
batching for async IO — is marginal for our workload, which is dominated by a few
**large-object streams**, not millions of tiny ops. The batching that helps
small-IO-heavy workloads buys little when each request moves gigabytes. Meanwhile
**kTLS maturity is tokio-native**: the `ktls` integration, rustls, and hyper all
sit on the tokio stack. Choosing an io_uring runtime would trade away the mature
kTLS path — our centerpiece — for a syscall-batching win we mostly can't use. So:
tokio, thread-per-core.

## One-pass MD5 (the unavoidable userspace touch)

S3 ETags are the MD5 of the object (and a composite MD5 for multipart). That is a
**mandatory single CPU pass** over the bytes on write — there's no avoiding it
without breaking S3 semantics. We make it the *only* userspace pass: PUT and
UploadPart run one `read → md5.update → pwrite` loop over a reused aligned buffer,
so hashing and persisting share the same pass and the payload is never fully held
in memory. GET needs no hash at all (the ETag is already in the sidecar), so reads
have zero gateway-side per-byte crypto/hash cost — only ZFS and (offloaded) TLS.

## Multipart: store parts + reassemble on read

`CompleteMultipartUpload` does **not** concatenate parts into one file. Instead it
moves the uploaded parts into a per-object `{key}.parts/` directory, writes the
object's `.s3meta` sidecar with an ordered part manifest (path, size, MD5 per
part), and computes the composite ETag from the part digests. GET keys off the
sidecar: a `MultipartReader` streams the part files back-to-back as one logical
body (with range support spanning parts), one fd and one reused buffer at a time.

**The tradeoff, stated plainly:** we trade a **write-time data rewrite** (copying
every byte of a large multipart object a second time just to concatenate it) for a
**per-GET scatter across part files** (a handful of sequential opens instead of
one). For large objects assembled from few large parts on NVMe, avoiding the
full-object rewrite at completion is the clear win; the read-side cost is a few
extra `open`/`close` calls at part boundaries, negligible against the bytes moved.
The only real downside is more inodes per object and slightly more complex GET
code — both acceptable for the throughput gained.

## Summary

The research conclusion drove everything: on encrypted ZFS RaidZ3 the per-byte
floor is in-kernel and fixed, so the gateway's whole job is to add nothing on top
of it. We remove TLS crypto (kTLS on the NIC), userspace copies (Direct IO), and
runtime overhead (thread-per-core), keep the one unavoidable userspace pass (ETag
MD5) folded into the streaming loop, and skip the multipart write-time rewrite by
reassembling on read. tokio + rustls + ktls is the stack that makes the
centerpiece — NIC TLS offload — work today.
