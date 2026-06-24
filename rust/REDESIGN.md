# Storage-Layer Redesign — Content-Addressed Blob Store

**Status:** DESIGN ONLY. No code in `src/`, `Cargo.toml`, or tests is changed by this
document. This is the implementable spec the coders work from.

**Scope:** rewrite ONLY the `storage` module (`src/storage/*`). The
server/auth/handler/s3response layers (thread-per-core + kTLS + hyper; SigV4; S3
XML/errors) are unchanged. The storage public API is held as close to today's as
possible so handler churn is near-zero (see §10).

---

## 0. Why we are doing this

The current layout maps an S3 key directly to a file path:

```
{data}/{bucket}/{key}                 # single-part data, OR 0-byte placeholder for multipart
{data}/{bucket}/{key}.s3meta          # JSON sidecar (manifest for multipart)
{data}/{bucket}/{key}.parts/00001     # multipart part files
```

Six review rounds (C1/C2/D1/E2/E3/F1/F2/F5/F7…) hardened the publish path into a
move-aside + stage-then-swap + rollback machine: `complete_multipart_upload` alone
is ~400 lines of "rename the old store aside, swap staging in, write placeholder,
commit sidecar, restore-everything-on-any-error." It is correct, but it is fragile
to extend, and it has one inherent **LOW-severity multipart torn-read window** that
the architecture cannot remove:

> A multipart object's parts live at fixed path strings `{key}.parts/NNNNN`. When
> the object is overwritten, `complete` swaps **new** part files into the **same**
> `{key}.parts/NNNNN` path strings. An in-flight GET that already opened the old
> manifest (old sizes/ETag) but has not yet opened a given part can open the **new**
> bytes at that path → old metadata paired with new bytes. The per-key `RwLock`
> (F2) narrows but does not eliminate this: the lock is dropped before the body
> streams (it must be — streaming a 100 GB object cannot hold a publish lock), and
> the open fd only pins what is *already* open.

The fix is structural: **make every blob immutable and uniquely named, so a path is
never reused.** A reader holding an old manifest references blob ids that no writer
will ever overwrite. The only thing that can happen to those blobs is *deletion*
(by reclaim), which fails the reader's `open()` with `ENOENT` → the GET truncates
(fail-fast). There is no path by which a reader can read the wrong bytes.

This eliminates the torn-read class **by construction** and collapses the publish
path to a single atomic `rename` of one small manifest file.

---

## 1. On-disk layout

```
{data}/
  {bucket}/
    current/                         # LIVE manifests, laid out as a KEY-PATH TREE
      a/b/c.meta                      #   object key "a/b/c"
      photo.jpg.meta                  #   object key "photo.jpg"
      report.meta.\x00meta            #   reserved-suffix escape (see §7.3)
    arriving/                        # in-flight uploads (manifests + part staging)
      {uuid}.meta                     #   staged manifest awaiting commit (PUT/Complete)
      {uuid}/                         #   multipart upload working dir
        upload.json                   #     {upload_id,bucket,key,initiated,ct,user_meta}
        parts/
          00001 -> blob? no — see §1.1
    deleted/                         # reclaim journal markers (durable to-delete lists)
      {uuid}.journal                  #   JSON: ["<blob_id>", "<blob_id>", ...]
    blobs/                           # IMMUTABLE, uniquely-named object data + parts
      ab/                             #   fanout level 1 (first 2 hex of blob id)
        cd/                           #   fanout level 2 (next 2 hex of blob id)
          ab cd 1f2e-...-uuid         #     the blob file (full uuid as the name)
```

There is **no** `{key}` data file and **no** `{key}.s3meta` sidecar at the key path
anymore. The only thing under `current/` is the `.meta` manifest tree. All bytes
live under `blobs/`.

### 1.1 Blobs

- A **blob** is an immutable file holding object data. For a single-part PUT the
  whole body is one blob. For multipart, **each part is one blob**.
- Blob id = a fresh **v4 UUID** (already a dependency). The blob's on-disk name is
  the full uuid string; its directory is derived by fanout (§1.2).
- Blobs are **per-bucket-owned and NOT deduplicated/refcounted** across objects.
  Each object *version* owns its blobs exclusively. When a version is superseded or
  deleted, *exactly that version's* blob ids are reclaimed. This is the property
  that makes the journal a simple "delete these N files" list with no refcount
  bookkeeping and no cross-object hazard.
- Blobs are written ONCE, fsynced (under `--fsync`), and never opened for write
  again. Reads use the existing `DioFile::open_read` (O_DIRECT + buffered fallback,
  O_NOFOLLOW). Writes use `DioFile::create_write` + the one-pass MD5 loop, unchanged.

**Where new blobs are written before commit:** directly into their final fanout
path under `blobs/`. A blob with a brand-new uuid name cannot collide with anything
and cannot be referenced by any live manifest until its manifest commits, so writing
it straight to `blobs/` is safe — an uncommitted blob is simply an orphan that the
recovery sweep's fallback GC (or the per-upload `arriving/{uuid}/` cleanup for
multipart) reclaims. (We keep a per-upload `arriving/{uuid}/` dir for multipart so
an *aborted/never-completed* upload's blobs are cheaply found and deleted without a
full GC — see §6.) For a single PUT we record the new blob id in the staged manifest
and, on any pre-commit failure, delete that one blob directly.

### 1.2 Fanout: 2 levels × 2 hex = 256 × 256 = 65 536 buckets

Blob `b3f1c2a4-...` → `blobs/b3/f1/b3f1c2a4-...`.

**Justification.** Target is "tens of millions of blobs." With 2×2 hex fanout there
are `256 * 256 = 65 536` leaf directories. At 50 M blobs that's ~**760 entries per
leaf dir** on average — comfortably small for ext4/XFS/ZFS directory operations (no
giant-directory `readdir`/`lookup` pathologies; well under the ~10 k-entries-per-dir
rule of thumb). One level (256 dirs) would give ~195 k entries/dir at 50 M — too
hot. Three levels (16.7 M dirs) would waste inodes and slow the recovery GC's
directory walk for no benefit at this scale. **2×2 is the chosen depth/width.** The
uuid is uniformly distributed, so fanout is even without hashing the key. (We fan
out on the blob id's own hex, not a separate hash — the uuid *is* the hash-quality
random string.)

`fn blob_path(bucket_root, blob_id) -> PathBuf` = `bucket_root/blobs/{id[0..2]}/{id[2..4]}/{id}`.
The two parent dirs are created lazily (`create_dir_all`) on first blob in that leaf.

---

## 2. The manifest (atomic commit unit)

One manifest file per live object key, at `current/{key-path}.meta`. Small JSON.

```rust
struct Manifest {
    key:            String,            // the full object key (authoritative; survives escaping)
    content_type:   String,
    content_length: u64,               // total logical size = sum(parts[].size)
    etag:           String,            // quoted. single-part: "md5". multipart: "md5-N".
    last_modified:  i64,               // unix seconds
    created:        i64,               // unix seconds (first write of this version)
    user_metadata:  BTreeMap<String,String>,   // x-amz-meta-*  (skip if empty)
    content_disposition: String,       // (skip if empty)
    content_encoding:    String,       // (skip if empty)
    cache_control:       String,       // (skip if empty)
    parts: Vec<PartRef>,               // ALWAYS present; len==1 for single-part
}

struct PartRef {
    part_number: u32,                  // 1-based; 1 for single-part
    blob_id:     String,               // uuid -> blobs/xx/yy/{blob_id}
    size:        u64,
    md5:         String,               // hex md5 of THIS blob's bytes (no quotes)
}
```

Design choices:

- `parts` is **always present** (single-part = a one-element list). This unifies the
  read path: there is exactly one reader type now (§8) — no `Option<multipart>`
  branch, no separate `PlainFileReader` vs `MultipartReader` split required (we can
  keep `PlainFileReader` as a fast path for `parts.len()==1`, but the manifest format
  no longer encodes "single vs multipart" as a structural fork).
- The single-part ETag is `"hex(md5(body))"`; the multipart composite ETag is
  `"hex(md5(blob_md5_1_raw || … || blob_md5_N_raw))-N"` — **identical formats to
  today** (the composite uses the 16-byte raw digests). The per-part `md5` field is
  the hex of that part's blob, reused both for the composite ETag and for
  ListParts/Complete validation.
- `blob_id` is a **uuid only**, never an absolute or relative path. The reader
  resolves it via `blob_path()`, so a crafted manifest cannot point a part at an
  arbitrary filesystem path (this removes the entire `validate_part_paths`
  canonicalize-every-part defense — there is no path to validate, only a uuid to
  syntactically check; see §11).

`ObjectMetadata` (the type handlers consume for headers) is derived from `Manifest`
trivially — we keep the public `ObjectMetadata` struct shape so the handler header
code (`apply_object_headers`) is unchanged (§10).

---

## 3. The commit protocol (PUT and multipart Complete)

This is the heart of the rewrite. **Publishing an object = atomically renaming one
manifest file into `current/`.** Precondition for both PUT and Complete: all new
blobs are already written and fsynced (under `--fsync`) to their final `blobs/`
paths, and we hold the per-key WRITE lock (§9).

Let `K = current/{escaped-key}.meta` be the live manifest path for the key.

```
PUBLISH(bucket, key, new_manifest):
  # (new blobs already written+fsynced to blobs/xx/yy/ )
  # hold per-key WRITE lock for the whole sequence

  1. stage:    write new_manifest to A = arriving/{uuid}.meta ; fsync A (if --fsync)
  2. journal:  if K exists:
                  read old manifest at K
                  J = deleted/{uuid}.journal   <- list of OLD manifest's blob_ids
                  write J ; fsync J ; fsync(deleted/) (if --fsync)
  3. COMMIT:   rename(A -> K)                  <- ATOMIC. After this, new version live.
               fsync(parent dir of K)          (if --fsync; best-effort, see note)
  4. reclaim:  for blob_id in J: delete blobs/xx/yy/{blob_id}
  5. cleanup:  delete J
```

`rename(A -> K)` atomically replaces the old manifest (POSIX rename-over guarantee).
The instant it returns, GETs see the new version; before it, GETs see the old. There
is no moment where K is absent or half-written. The new blobs were already durable;
the old blobs are still on disk and still referenced by nothing live (K now names the
new manifest) but recorded in J for deterministic reclaim.

> **Note on step 3's dir-fsync:** as in today's `commit_metadata_temp` (D2), the
> rename is THE commit point; the post-rename `fsync(parent)` is a *best-effort
> durability* step whose failure is logged (`tracing::warn`) and **swallowed**, never
> rolled back. The object is published once the rename succeeds.

### 3.1 Crash analysis — PUBLISH

Let "live version" = whatever `current/{key}.meta` resolves to + the blobs it
references. We show: (a) no data-loss window, (b) every orphan is deterministically
cleanable.

| Crash after… | `current/K` resolves to | New blobs | Old blobs | J | Recovery action | Outcome |
|---|---|---|---|---|---|---|
| **new blobs written, before step 1** | OLD manifest | orphaned in `blobs/` | live (referenced by K) | — | fallback GC (or `arriving/{uuid}/` cleanup for MP) deletes orphan new blobs | OLD version fully live; new blobs reclaimed. **No loss.** |
| **step 1 (A staged), before step 2** | OLD manifest | orphaned | live | — | sweep: `arriving/*.meta` is an uncommitted manifest → delete A; new blobs reclaimed by GC/MP-cleanup | OLD version fully live. **No loss.** |
| **step 2 (J written), before step 3** | OLD manifest | orphaned | live (still referenced by K) | J lists OLD blobs | sweep: A in `arriving/` → delete. **J lists blobs still referenced by the LIVE manifest K** → see §3.2 | OLD version fully live; J must NOT be blindly executed. **No loss** (with §3.2 rule). |
| **step 3 rename done, before step 4** | NEW manifest | live | orphaned (J still present) | J lists OLD blobs | sweep: finish J's deletes (idempotent), remove J | NEW version live; OLD blobs reclaimed. **No loss.** |
| **step 4 partial (some old blobs deleted), before step 5** | NEW manifest | live | partially deleted | J present | sweep: re-run J deletes (delete of a missing file is a no-op), remove J | NEW version live; reclaim completed. **No loss.** |
| **step 5 (J removal) crash** | NEW manifest | live | deleted | J present (empty work) | sweep re-runs J (all deletes are no-ops), removes J | idempotent. **No loss.** |

**(a) No data-loss window.** The OLD version is fully live and self-consistent
(manifest + all its blobs present) up to and including the instant before the step-3
rename. The NEW version is fully live (manifest + all its blobs present, blobs were
fsynced in the precondition) the instant after the step-3 rename. The rename is
atomic, so there is no in-between.

**(b) No uncleanable orphan.** Uncommitted manifests live in `arriving/` and are
deleted wholesale by the sweep. New blobs that never got a committed manifest are
reclaimed either by the multipart `arriving/{uuid}/` per-upload cleanup or, for a
single PUT that crashed before commit, by the fallback GC (their uuid is referenced
by no live manifest). Old blobs are reclaimed by the journal. Every orphan maps to
exactly one deterministic sweep action.

### 3.2 The journal-vs-live-manifest hazard, and how the protocol avoids it

The step-2 row above flags a real subtlety: if we crash *after* writing J (which
lists the OLD blobs) but *before* the rename, then `current/K` still points at the
OLD manifest — whose blobs J is about to delete. A naive "sweep executes all
journals" would then delete blobs the live manifest still needs. **This is the one
ordering rule that must be exactly right.** Two complementary defenses, both
specified, pick **Defense A** as primary:

- **Defense A (chosen) — couple the journal lifetime to the commit, by making the
  journal a *post-commit* artifact in effect.** We write J in step 2 but the sweep
  treats a journal as executable **only once the corresponding commit is known to
  have happened.** We encode that by putting the *new* manifest's identity into the
  journal and checking it at sweep time:

  ```
  J = { "supersedes_key": "<escaped key>",
        "expected_new_etag": "<new manifest etag>",   # identity of the version that REPLACES old
        "blobs": ["<old_blob_id>", ...] }
  ```

  Sweep rule for a journal J: read `current/{J.supersedes_key}.meta`.
    - If it exists **and** its `etag == J.expected_new_etag` → the commit happened;
      execute J's deletes (idempotent) and remove J.
    - If it exists but `etag != J.expected_new_etag` → the commit did **not** happen
      (K is still the OLD version, or a *different* newer version already replaced it
      and wrote its *own* journal for these same old blobs). In the "still OLD"
      sub-case the OLD blobs are still live → **do NOT delete; remove J only if K's
      etag is neither old-expected-new nor… ** — to keep this unambiguous we add
      `old_etag` too (below) and the simple safe rule: *delete blobs only when the
      live manifest's etag matches `expected_new_etag`; otherwise leave the blobs and
      delete J* (the blobs are then either still-live-old, reclaimed by a later
      journal, or genuine orphans swept by the fallback GC).
    - If it does not exist (object later deleted) → a DELETE journal (§5) already
      owns these blobs, or the fallback GC will; delete J.

  Because v4 ETags differ between versions, `expected_new_etag` uniquely
  distinguishes "my commit landed" from "it didn't." Edge: two PUTs with *identical
  bytes* (same md5 → same single-part etag). Then `expected_new_etag` collides. We
  disambiguate by also storing `manifest_uuid` (the `arriving/{uuid}` name that
  became K is not observable post-rename, so instead store a random `commit_nonce`
  inside the manifest JSON itself and copy it into the journal). The live manifest
  carries `commit_nonce`; the journal carries the *new* version's `commit_nonce`; the
  sweep compares nonces. Identical-bytes PUTs get distinct nonces. **This nonce is
  the authoritative "did my commit land" check; etag is a fast pre-filter.**

- **Defense B (fallback, always on) — the full GC never deletes a referenced blob.**
  Even if a journal rule were mis-evaluated, the fallback GC (§6) only deletes blobs
  **not referenced by any live manifest**, so a blob the live OLD manifest needs is
  never collected. Defense B makes blob deletion *monotonically safe*: the journal is
  an *optimization* that avoids a full O(blobs) scan in the common path; correctness
  of "never delete a live blob" rests on the reference check, which the journal's
  nonce rule and the GC both honor.

> **Implementation guidance:** keep the journal record small and self-describing
> (`commit_nonce`, `supersedes_key`, `blobs[]`). The sweep's per-journal decision is:
> "does the live manifest at `supersedes_key` carry exactly `commit_nonce`? If yes,
> these blobs are now unreferenced — delete them. If no, leave the blobs, delete the
> journal." This is O(1) per journal plus one small manifest read; no full scan.

### 3.3 Why this is simpler than today

Today's `complete_multipart_upload` does: stage sidecar → move old parts-store aside
→ swap staging into the *reused* `{key}.parts` path → aside the old `{key}` data file
→ write a 0-byte placeholder → commit sidecar → on *any* of ~8 failure points, run a
multi-branch `restore_old!`/`restore_staged_parts!` macro that funnels parts back to
the upload dir. All of that exists because **parts and the data file live at reused
paths** that must be move-aside/restored transactionally.

With immutable blobs there is **nothing to move aside**. The old version's blobs stay
exactly where they are; the new version's blobs are at *new* paths; commit is one
rename; rollback is "delete the new blobs I wrote and the staged manifest." The
`restore_*` machinery, the `.parts.new.<uuid>`/`.parts.old.<uuid>` dance, the 0-byte
placeholder, the `KeyPrefixConflict`-on-aside logic — all gone. (Key/prefix conflict
is handled differently now; see §7.2.)

---

## 4. DELETE protocol

```
DELETE(bucket, key):
  # hold per-key WRITE lock
  1. K = current/{escaped-key}.meta
  2. if K absent -> idempotent success (after head_bucket check, C7 preserved)
  3. read old manifest at K  -> blob list
  4. J = deleted/{uuid}.journal = {commit_nonce: NONE_DELETE_SENTINEL,
                                   supersedes_key: key, mode: "delete",
                                   blobs: [old blob ids]} ; fsync J ; fsync(deleted/)
  5. COMMIT: remove(K) ; fsync(parent) (best-effort)
  6. reclaim: delete each blob in J
  7. cleanup: delete J
  8. prune now-empty ancestor dirs in current/ up to (not incl.) current/  (as today)
```

A DELETE journal uses `mode: "delete"` and the sweep rule becomes: *if K is absent,
execute the deletes (idempotent) and remove J; if K is present, the delete didn't
commit (or the key was re-created) — leave the blobs (the re-created version owns its
own, distinct blobs; these old ones are unreferenced and the GC will get them) and
remove J.* Crash analysis mirrors §3.1: K present ⇒ old version fully live; K absent ⇒
delete committed, blobs reclaimed; J replays idempotently.

---

## 5. Reader semantics — the window this closes

```
GET(bucket, key, range):
  # take per-key READ lock ONLY around the manifest read (see §9 for whether even
  # this is still needed) — NOT around the body stream.
  1. read manifest at current/{escaped-key}.meta   <- ONE atomic file = consistent snapshot
  2. (lock may be released here)
  3. resolve range against manifest.content_length
  4. open blobs referenced by manifest.parts in order, stream them back-to-back
```

The manifest is a single file produced by an atomic rename, so step 1 yields a
**consistent snapshot**: key, content-length, etag, and the *exact blob ids* of one
version. A concurrent overwrite writes **new** blobs at **new** uuid paths and renames
in a **new** manifest; it never touches the blob ids our snapshot captured.

Therefore the in-flight reader keeps reading the OLD blobs successfully **unless** the
reclaim (publish step 4 / delete step 6) deletes an old blob *mid-stream*. In that
case the reader's `open()` of that blob fails `ENOENT`, or a blob it already opened is
unlinked (the fd keeps the inode alive on POSIX until close, so an already-open blob
streams fine; only a not-yet-opened blob can ENOENT). On ENOENT/short-read the reader
**returns an error that truncates the HTTP body** — exactly the existing
`MultipartReader` behavior (`UnexpectedEof` / `NotFound` → the GET channel forwards the
`io::Error`, the body ends short, the client sees a truncated/failed transfer rather
than mixed bytes). This is the **already-accepted GET-vs-DELETE semantics**.

**Consistency contract (state explicitly):**

> **A GET returns a single consistent version or it fails. It never returns mixed
> bytes from two versions.**

No inode/mtime fingerprinting is needed (today's reader does not fingerprint, and now
it provably cannot need to): a uuid blob name is never reused, so a path that opens
successfully *is* the snapshot's blob — there is no silent-swap possibility to detect.

(For single-part objects this is even simpler: one blob, one open. ENOENT → truncate;
otherwise the full body. The fd pins the inode for the whole stream once opened.)

---

## 6. Crash-recovery sweep

Runs at **startup** (mandatory) and **optionally periodically**. Idempotent.

```
SWEEP(data_root):
  for each bucket dir:
    # 6.1 arriving/  — uncommitted uploads
    for entry in arriving/:
      if entry is "{uuid}.meta" (staged single-PUT/Complete manifest that never committed):
          delete it.   (its new blobs become GC's job, or were already deleted on the
                        failed-publish rollback; either way safe)
      if entry is "{uuid}/" (multipart working dir):
          # an upload that was created but never completed (or crashed mid-complete)
          read upload.json; the part blobs for THIS upload are recorded there / or in
          arriving/{uuid}/parts.json -> delete those blobs, then remove the dir.
          (If completed successfully, complete_multipart_upload already removed this dir.)

    # 6.2 deleted/  — reclaim journals (finish the deletes)
    for J in deleted/*.journal:
      apply the §3.2 / §4 nonce rule:
        read current/{J.supersedes_key}.meta (if any)
        if J.mode=="publish": delete J.blobs IFF live manifest's commit_nonce == J.commit_nonce
        if J.mode=="delete" : delete J.blobs IFF live manifest is ABSENT
        (deletes are idempotent: unlink-missing == ok)
      remove J

    # 6.3 FALLBACK full GC  (infrequent / offline — see safety note)
    #   reclaims blobs orphaned by a LOST journal (e.g. fs lost deleted/ entry).
    referenced = {}                                  # set of blob ids
    walk current/**.meta -> for each manifest, add all parts[].blob_id to referenced
    also add blob ids referenced by in-flight arriving/{uuid}/ uploads (don't GC live uploads)
    for blob in blobs/**:
      if blob.id NOT in referenced AND blob older than GRACE: delete blob
```

**6.1 / 6.2 are O(arriving + journals)** — cheap, run every startup, safe to run while
live (they only touch uncommitted/under-reclaim artifacts; see concurrency note).

**6.3 is O(total blobs)** and is the *fallback*: it only matters if a journal was lost
(should be near-never with `--fsync`). It is the ultimate backstop that makes blob
deletion correct regardless of journal integrity (Defense B, §3.2).

### 6.4 Concurrency safety of the sweep vs live traffic

- **6.1 (arriving cleanup):** an `arriving/{uuid}.meta` or `arriving/{uuid}/` that a
  *live in-progress* request is currently using must not be reaped. Distinguish with a
  **grace window**: only reap `arriving/` entries whose mtime is older than `GRACE`
  (e.g. 1 h, ≫ any legitimate upload-to-complete gap) — OR run 6.1 **at startup only**
  (no live traffic yet). **Chosen:** run 6.1+6.2 at startup before the listener binds
  (zero live traffic → unconditionally safe, no grace needed); the optional periodic
  re-run uses the GRACE window for 6.1.
- **6.2 (journals):** safe to run live. The nonce rule deletes only blobs the live
  manifest does not reference; a concurrent publish for the same key holds the per-key
  WRITE lock and writes a *new* journal with a *new* nonce, so the two journals address
  disjoint blob sets. Worst case a blob deletion races a GET that is about to open it →
  ENOENT → truncate (the accepted GET-vs-reclaim semantics, §5).
- **6.3 (full GC):** the dangerous one for live traffic, because a blob written by an
  in-flight PUT (already in `blobs/` but not yet committed) would look "unreferenced."
  Mitigations: (a) only collect blobs older than `GRACE`; (b) treat blob ids referenced
  by any `arriving/{uuid}/` upload as referenced; (c) **recommend running 6.3 only at
  startup or as an explicit offline/maintenance op**, never on the default periodic
  timer. Documented as O(blobs), infrequent.

**Chosen policy:** startup runs 6.1 + 6.2 + 6.3 (clean slate, no traffic). A periodic
timer (if enabled) runs 6.1 + 6.2 only, with GRACE; 6.3 is opt-in/manual.

---

## 7. Listing (the recorded open decision)

### 7.1 Decision: KEY-PATH TREE, not hash+index

**Chosen:** manifests are stored as a key-path tree under `current/` (object `a/b/c` →
`current/a/b/c.meta`), and `ListObjectsV2` is a `filepath::WalkDir`-style walk of
`current/`, identical in spirit to today's `walk_dir`. Strip the `.meta` suffix to
recover the key, filter by prefix, group by delimiter into CommonPrefixes, sort, then
paginate with `max-keys` / `continuation-token` / `start-after` — the **existing
`list_objects` algorithm is reused almost verbatim**, only the per-entry decode changes
(read the `.meta` manifest for size/etag/last-modified instead of a `.s3meta` sidecar;
strip `.meta` instead of skipping `.s3meta`).

**Tradeoff.** A key-path tree gives sorted-prefix listing and delimiter grouping *for
free* from the directory structure, with **no external index** to keep consistent with
the blobs (an index would be a second source of truth that the commit protocol would
have to update atomically — reintroducing exactly the kind of multi-artifact
transaction we are trying to delete). The cost is the **flat-bucket caveat** below.

**Rejected alternative:** hash-prefix-fanout the manifests too (like blobs) + maintain
a separate ordered key index (embedded LSM/B-tree). This scales listing to millions of
flat keys but adds a transactional index update to every publish/delete and a recovery
story for the index. Given the gateway's stated target (throughput on large objects,
single machine), that complexity is not justified. **We consciously choose the tree.**

### 7.2 Flat-bucket caveat (documented)

A bucket with millions of keys that contain **no `/`** produces millions of `.meta`
files in a **single** `current/` directory — a large directory that slows `readdir`
and listing latency/memory (today's walk-and-buffer has the same memory profile;
DESIGN.md already documents "listing memory scales with bucket size"). This is an
accepted limitation for the single-machine target. Keys *with* `/` fan out naturally
into the tree and are unaffected. If flat-bucket scale ever becomes a requirement,
that is when the rejected hash+index option would be revisited.

Also note: **key/prefix conflict** is GONE on the CAS object path. Today a nested key
`a/b` makes `a/` a real directory, so a later PUT of `a` (a file at a dir path) raised
`KeyPrefixConflict` (409). In the tree (encode v2, §7.3), `a/b` →
`current/a/b.s3gw-live.meta` makes `current/a/` a directory and PUT of key `a` wants
`current/a.s3gw-live.meta` — **different paths**, so they **coexist with no conflict**,
which is *more* S3-faithful (real S3 lets `a` and `a/b` both exist). The longer
`MANIFEST_SUFFIX` further dissolves the `a` vs `a.meta/b` corner (also distinct paths),
and the single residual collision (`a` vs `a.s3gw-live.meta/b`) is prevented up front by
the reserved-suffix rejection. **Implemented decision:** the new CAS store (`cas.rs`)
removed `detect_prefix_conflict` and all `KeyPrefixConflict`/409 detection/call sites on
the object path. The `StorageError::KeyPrefixConflict` variant + `S3ErrorCode` + the
handler 409 mapping are LEFT DEFINED (still produced by the not-yet-cut-over old
`filesystem.rs` impl); they become dead once the cutover removes `filesystem.rs`. This
removes the F1 move-aside-a-subtree hazard entirely.

### 7.3 Reserved-suffix handling — CAS encode v2 (IMPLEMENTED)

**Implemented decision (supersedes the `.meta`/`\x00m`-escape sketch below):** the live
manifest suffix is a single, distinctive, easily-changed constant

```rust
pub const MANIFEST_SUFFIX: &str = ".s3gw-live.meta";
```

The manifest for key `K` is the FILE `current/{leaf}{MANIFEST_SUFFIX}`, where `{leaf}` is
`K`'s final `/`-segment and every earlier segment is a **raw directory name** (no
transform):

- `a`        → `current/a.s3gw-live.meta`
- `a/b`      → `current/a/b.s3gw-live.meta`            (raw dir `a/`)
- `a/b/c`    → `current/a/b/c.s3gw-live.meta`          (raw dirs `a/`, `a/b/`)
- `a.meta`   → `current/a.meta.s3gw-live.meta`         (ordinary `.meta` keys are fine)

**Reserved-suffix rule (the entire reservation).** Reject — 400 InvalidArgument
(`StorageError::PathTraversal`) — any key where ANY `/`-split segment ends in
`MANIFEST_SUFFIX` (leaf OR ancestor: a non-leaf segment becomes a raw directory and a
raw dir ending in the suffix would collide with a manifest file). Combined with the
existing guards (empty key, empty segments, `..`, `.`, NUL, absolute), this makes the
key↔path map a **collision-free bijection by construction**, so the old runtime
`KeyPrefixConflict`/409 check is no longer needed: `a` + `a/b` and `a` + `a.meta/b`
freely COEXIST at distinct paths (more S3-faithful), and the only residual clash —
`a` (FILE `current/a.s3gw-live.meta`) vs `a.s3gw-live.meta/b` (needs DIRECTORY
`current/a.s3gw-live.meta/`) — is impossible because the latter is rejected up front.

**decode (listing) = exact inverse of encode.** Under `current/`, a FILE → strip the
trailing `MANIFEST_SUFFIX` to recover the leaf and join with the raw ancestor dir
names; a DIRECTORY → a raw key-prefix ancestor (never decoded). No escape to reverse.

This replaces both the old `.meta`-double-suffix scheme (`report.meta` →
`report.meta.meta`) AND the `\x00m`-escape sketch (a NUL is rejected by the OS in an
on-disk filename anyway). Staged temps in `arriving/` are uuid-named
(`arriving/{uuid}.manifest`) and journals (`deleted/{uuid}.journal`) are NOT key-derived,
so they do not use `MANIFEST_SUFFIX`; only the live `current/` manifests do.

**KNOWN LIMITATION (documented):** an object key may not contain a `/`-segment ending in
`MANIFEST_SUFFIX` (`.s3gw-live.meta`). This is the single structural reservation the
on-disk manifest tree requires; such keys are rejected with 400 InvalidArgument.

---

_Original design sketch (NOT implemented — kept for context):_

- Define `META_SUFFIX = ".meta"` and escape a `.meta`-suffixed final segment as
  `…{segment}\x00m.meta`. Rejected because (a) a NUL is unusable as an on-disk filename
  byte, and (b) the longer distinctive `MANIFEST_SUFFIX` removes the need for any escape
  while also dissolving the `K` vs `K.meta/…` collision (the §7.2 `KeyPrefixConflict`).

---

## 8. Reader implementation

Keep the existing readers nearly as-is, repointed at blobs:

- `parse_range`, `ByteRange` — **unchanged**.
- A single `BlobChainReader` (rename/refactor of today's `MultipartReader`) streams
  `manifest.parts` in order: resolve each `PartRef.blob_id` via `blob_path()`, open with
  `DioFile::open_read`, stream with the reused `AlignedBuf`, supporting a logical byte
  range spanning blobs. Today's `MultipartReader` already does exactly this over
  `PartRef.path`; the only change is `blob_path(blob_id)` instead of `PathBuf::from(&p.path)`.
- `parts.len()==1` may use `PlainFileReader` (open the single blob) as a micro-opt, or
  just use `BlobChainReader` uniformly. **Recommendation:** keep `PlainFileReader` for
  the single-blob fast path (it's already there and tested), select it when
  `parts.len()==1`.
- The short-blob / missing-blob → `UnexpectedEof`/`NotFound` error behavior (today's
  `multipart_missing_part_errors_not_truncates`) is preserved verbatim and is exactly
  the §5 fail-fast contract.

`GetObjectResult` (metadata + boxed `Read` + resolved_range + total_size) is unchanged,
so `handler::object::object_response` is unchanged.

---

## 9. Concurrency / locking

Keep the **sharded 256-shard per-`{bucket}/{key}` `RwLock`** table (`Arc<Vec<RwLock<()>>>`,
FNV-1a shard hash) — it is cheap and correct. But its role narrows:

- **Publish (PUT / Complete) and Delete: per-key WRITE lock, REQUIRED.** Held across the
  whole commit sequence (stage manifest → journal → rename → reclaim → cleanup) so two
  writers for the same key cannot interleave their journal/rename and so a Delete cannot
  race a Complete. This serializes manifest swaps and journal creation for one key.
  Concurrent writers to *different* keys never contend (different shard, almost always).
  The streaming blob *writes* run **before** the lock is taken (lock-free, fully
  parallel) — only the tiny commit critical section is serialized, exactly as today.
- **UploadPart vs Complete:** UploadPart writes its part **blob** to a fresh uuid path
  (no shared path), records the `(part_number → blob_id, size, md5)` in the upload's
  `arriving/{uuid}/parts.json` (or one tiny file per part) **under the per-key WRITE
  lock for the record append only** (the blob write itself is lock-free). Complete reads
  that part record under the same per-key WRITE lock. Because parts are immutable blobs
  at unique paths, the **E3 TOCTOU is gone**: Complete validates the part blobs it will
  reference (by blob_id), and no concurrent UploadPart can replace the bytes behind a
  blob_id (a re-uploaded part number gets a *new* blob_id; the part record append is
  serialized by the lock, so Complete sees a consistent `part_number → blob_id` map).
- **GET: does the per-key READ lock still need to be held?**
  **Analysis:** the only thing GET must read atomically is the manifest, and the
  manifest is published by a single atomic `rename`. An `open`+`read` of `current/K.meta`
  observes either the pre-rename inode or the post-rename inode — never a torn file
  (rename is atomic; we never write-in-place over a live manifest). The blobs the
  manifest names are immutable. **Therefore GET does NOT strictly need the per-key read
  lock for correctness** — atomic rename + immutable blobs already guarantee a
  consistent snapshot. This is a real simplification vs today's F2 (which needed the
  read lock precisely because parts lived at *reused* paths).
  **Recommendation (defense-in-depth, low cost):** still take the per-key READ lock for
  the *duration of the single manifest read* (a few microseconds), then drop it before
  streaming. It costs essentially nothing, makes the "snapshot" explicit, and guards
  against a future change that reintroduces in-place manifest mutation. Mark in code that
  it is *not* required for the immutable-blob invariant, only belt-and-suspenders. **The
  lock is NOT held during the body stream** (same as today — a 100 GB stream cannot pin a
  lock).

Poison-tolerance, the test-only contention probe, and the shard-hash function carry over
unchanged.

---

## 10. New `storage` module public API (minimize handler churn)

Goal: handlers call the **same method names with the same signatures** wherever possible.
Below, "unchanged" = identical signature to today; "internal-only" = behavior changes but
the signature handlers see does not.

```rust
impl Filesystem {
    pub fn new(root) -> Self;                                  // unchanged
    pub fn with_fsync(root, fsync: bool) -> Self;              // unchanged (--fsync preserved)
    pub fn root(&self) -> &Path;                               // unchanged

    // Bucket — unchanged signatures. create_bucket now also creates the
    // current/ arriving/ blobs/ deleted/ subdirs (or they are created lazily).
    pub fn create_bucket(&self, name) -> Result<()>;
    pub fn head_bucket(&self, name) -> Result<()>;
    pub fn delete_bucket(&self, name) -> Result<()>;          // "empty" = current/ empty (ignore the 4 infra dirs)
    pub fn list_buckets(&self) -> Result<Vec<BucketInfo>>;

    // Object — signatures UNCHANGED.
    pub fn put_object<R: Read>(&self, bucket, key, body: R, content_type, user_meta) -> Result<String>;  // -> etag
    pub fn get_object(&self, bucket, key, range_header: Option<&str>) -> Result<GetObjectResult>;
    pub fn head_object(&self, bucket, key) -> Result<ObjectMetadata>;
    pub fn delete_object(&self, bucket, key) -> Result<()>;

    // Listing — signature UNCHANGED.
    pub fn list_objects(&self, input: &ListObjectsInput) -> Result<ListObjectsOutput>;

    // Multipart — signatures UNCHANGED.
    pub fn create_multipart_upload(&self, bucket, key, content_type, user_meta) -> Result<String>;
    pub fn upload_part<R: Read>(&self, bucket, key, upload_id, part_number: i32, body: R) -> Result<String>;
    pub fn complete_multipart_upload(&self, bucket, key, upload_id, parts: &[CompletePart]) -> Result<String>;
    pub fn abort_multipart_upload(&self, bucket, key, upload_id) -> Result<()>;
    pub fn list_parts(&self, bucket, key, upload_id) -> Result<Vec<PartInfo>>;
    pub fn list_multipart_uploads(&self, bucket, max_uploads: usize) -> Result<(Vec<MultipartUpload>, bool)>;

    // NEW (not called by handlers; called by main/server at startup, and optional timer):
    pub fn recover(&self) -> Result<RecoveryStats>;            // runs SWEEP 6.1+6.2(+6.3 at startup)
}
```

**Public types kept identical** so handlers/response code don't change: `GetObjectResult`,
`ObjectMetadata` (the `multipart: Option<Vec<PartRef>>` field can stay for wire/header
compatibility, populated from `manifest.parts` when `len>1`, OR we keep `ObjectMetadata`
purely as the handler-facing header bundle and derive it — either way the *handler* sees
the same struct), `ObjectInfo`, `BucketInfo`, `ListObjectsInput`, `ListObjectsOutput`,
`MultipartUpload`, `PartInfo`, `CompletePart`, `StorageError`, `validate_bucket_name`.

**Signatures that may change (flag for the orchestrator):**
- `PartRef` gains `blob_id` and drops `path` (it is an internal manifest type, but it is
  re-exported in `storage/mod.rs` and used by `reader.rs` and a few `metadata` tests).
  Handlers do not touch `PartRef` directly, so this is contained to the storage module +
  its unit tests.
- `META_SUFFIX` changes value `".s3meta"` → `".meta"`; `MULTIPART_DIR` (`.multipart`) is
  replaced by the per-bucket `arriving/`+`blobs/`+`deleted/` infra (the constant may be
  removed or repurposed). These are re-exported but not used by handlers.
- `StorageError::KeyPrefixConflict` becomes unreachable on the object path (§7.2);
  decision to keep-but-dead or remove is an open item (§13).

`main.rs` change: after `Filesystem::with_fsync(...)`, call `fs.recover()?` **before**
the server binds its listeners. One line. (Today main.rs builds the fs and starts the
server; we insert the startup sweep between.)

---

## 11. What is preserved verbatim (do NOT redesign)

- **Direct-IO**: `DioFile` (O_DIRECT + buffered fallback, O_NOFOLLOW on every open),
  `AlignedBuf` (ALIGN=4096, DEFAULT_BUF_SIZE=1 MiB), `aligned.rs`, `directio.rs` — used
  unchanged for all blob read/write.
- **One-pass MD5** on PUT and UploadPart (read→md5.update→pwrite over the reused buffer);
  the object is never materialized in memory. The blob is the write target instead of a
  `{key}.tmp` file.
- **Reassemble-on-read** (manifest → sequential blob streaming) via `BlobChainReader`
  (today's `MultipartReader`), range support spanning blobs.
- **O_NOFOLLOW / containment**: every blob/manifest open uses O_NOFOLLOW; bucket-name
  validation, NUL/`..`/absolute-key rejection, and the canonical-root containment checks
  carry over. **The `validate_part_paths` per-part canonicalize is removed** because part
  references are now uuids resolved through `blob_path()` (no client- or manifest-supplied
  path is ever opened) — a strict net reduction in attack surface. The symlinked-`.multipart`
  /upload-dir checks (`multipart_root`, `upload_dir` canonicalize) are replaced by the same
  discipline applied to `arriving/{uuid}/` (validate uuid syntactically; reject a symlinked
  arriving dir).
- **`--fsync`** flag and its meaning (data always fsynced; manifest/journal/dir fsyncs
  gated by the flag) — preserved; the protocol's fsync points (§3 steps 1,2,3; §4 step 4,5)
  are all gated by `self.fsync`, with the data-blob fsync always on.
- **All S3 semantics**: single-part ETag `"md5"`; composite ETag `"md5-N"` over raw
  16-byte digests; Range/206/416 with `Content-Range`; `x-amz-meta-*`, content-type,
  content-encoding, content-disposition, cache-control round-trip; the full `StorageError`
  → `S3ErrorCode` mapping; idempotent DELETE (C7 NoSuchBucket); ListObjectsV2 pagination
  semantics (absent vs `Some(0)` max-keys, F14; continuation token = last emitted item, C6);
  ListMultipartUploads cap + IsTruncated (E7, MAX_UPLOADS_CAP).
- The server/auth/handler/s3response layers entirely.

---

## 12. Migration: CLEAN BREAK

**Recommendation: clean break. No on-disk migrator.** The gateway is pre-deployment
(per the brief), so there is no production data in the old `{key}` + `{key}.s3meta` +
`{key}.parts/` layout to preserve. Writing a migrator (walk old sidecars → mint blob
uuids → move part/data files into `blobs/` → write `current/*.meta` + a one-shot journal
sweep) is *possible* and not enormous, but it is pure throwaway code for a format no
deployment runs. **Decision:** ship the new layout only; the old layout is unreadable by
the new code. If a stray old-format data dir is pointed at the new binary, listing/GET
simply find no `current/` manifests and report empty/NoSuchKey (no corruption, no crash) —
acceptable for a pre-deployment clean break. Document this in README/DESIGN.

### Test impact

- **Rewritten (layout-coupled):** all **70 unit tests in `filesystem.rs`** (they assert on
  `{key}.s3meta`, `.parts`, placeholder files, aside/rollback internals), the **5 in
  `metadata.rs`** (PartRef.path, sidecar format), and the **7 in `reader.rs`** (PartRef.path
  → blob_id). These are the bulk of the storage rewrite's test work. New tests are added
  for the commit protocol, journal/sweep, and concurrent-overwrite-during-GET (§14).
- **Unaffected (no rewrite):** `auth/sigv4.rs` (25), `auth/chunked_reader.rs` (10),
  `auth/credentials.rs` (7), `auth/time.rs` (5), `s3response/xml.rs` (6),
  `s3response/errors.rs` (4), `handler/mod.rs` (4), `handler/object.rs` (1),
  `handler/list.rs` (1), `server/router.rs` (4), `config.rs` (2), `directio.rs` (3),
  `aligned.rs` (3). That's **~78 of 157** tests untouched (they exercise APIs/types whose
  signatures we hold stable).
- **`scripts/smoke.sh` (19 checks)** and the **e2e suite (`tests/server_e2e.rs`, 7 fns)**
  drive the gateway through HTTP — they assert S3 *behavior*, not on-disk layout — so they
  must continue to pass **unchanged** (this is the primary end-to-end gate). They are the
  proof the public contract held across the rewrite.

---

## 13. Risks / open questions for the orchestrator/human to confirm

1. **`KeyPrefixConflict` removal (§7.2).** The tree layout makes `a` and `a/b` naturally
   coexist (more S3-faithful), so the F1 conflict + its move-aside hazard vanish. Confirm
   we WANT that behavior change (real S3 allows both). If yes: remove/deaden the variant +
   the `KeyPrefixConflict` S3 error code mapping; update any test asserting 409. **Recommend
   yes.**
2. **Journal nonce rule (§3.2).** The "delete old blobs IFF live manifest's `commit_nonce`
   matches" rule is the one correctness-critical piece. Confirm the `commit_nonce` approach
   (vs relying solely on the fallback GC). **Recommend nonce as primary + GC as backstop**
   (both specified).
3. **Single-part blob in `blobs/` before commit vs an `arriving/` staging file.** §1.1 writes
   single-PUT blobs straight to `blobs/` (orphan-on-crash, GC-reclaimed). Alternative: stage
   the blob under `arriving/{uuid}/` and rename into `blobs/` at commit. Straight-to-blobs is
   simpler and avoids an extra rename of (potentially huge) data; the only cost is relying on
   GC for a crashed-before-commit single PUT. **Recommend straight-to-blobs.** Confirm.
4. **Periodic full GC (6.3).** Default OFF (startup + manual only) to avoid the live-traffic
   "unreferenced-but-in-flight blob" hazard. Confirm we don't want it on a timer; if we do,
   the GRACE+arriving-referenced mitigations (§6.4) are mandatory.
5. **Flat-bucket caveat (§7.2)** is an accepted limitation (same memory profile as today's
   walk-and-buffer). Confirm it stays a documented non-goal rather than a blocker.
6. **`MultipartUpload` part bookkeeping location.** §9 records `part_number→blob_id` in
   `arriving/{uuid}/parts.json` (or one file per part). Confirm the single-JSON approach
   (simpler, but rewritten under the per-key lock on each UploadPart) vs one-tiny-file-per-part
   (more inodes, lock-free-er). **Recommend one file per part** named `parts/{NNNNN}.ref`
   (tiny JSON `{blob_id,size,md5}`), so UploadPart only creates its own file (no shared-file
   rewrite) and Complete reads the dir — closest to today's `parts/{NNNNN}` model and keeps
   UploadPart maximally parallel. (Updated recommendation; supersedes the single-JSON note in §9.)

### 13.6 Codex review pass B — resolutions & accepted limitations (IMPLEMENTED)

- **B1 — Complete moves part blobs to fresh manifest-owned ids (live-data-loss fix, IMPLEMENTED).**
  `CompleteMultipartUpload` no longer references the upload's part-blob ids verbatim. After the
  A7 blob-stat, each part blob is MOVED to a fresh manifest-owned uuid via a same-filesystem
  `rename(2)` (`blob::move_blob_to_new_id`) — O(1), **no data copy**, so the one-pass-MD5 /
  no-copy payload invariant is preserved. The manifest references the NEW ids; the upload's
  surviving `parts/*.ref` then point at the moved-away (now-ENOENT) OLD ids, so a stale upload
  dir (best-effort rmdir failed, or a crash after publish) can NEVER cause a later Abort /
  `gc_abandoned_uploads` / Complete-RETRY to delete the live object's blobs (the `commit_nonce`
  rule alone could not protect this — old & new previously shared ids).
  - *Retryability (E2):* if any per-part rename OR the subsequent commit fails, the renames done
    so far are ROLLED BACK (each blob moved back to its original `.ref` id) and the error is
    returned, leaving the upload intact and retryable.
  - *Crash edge (accepted):* a crash MID-rename is safe — the manifest is not committed yet, so
    no live object is affected; the partially-moved blobs become orphans the **opt-in**
    `gc_orphan_blobs` reclaims (an in-flight upload dir's part blobs are otherwise treated as
    referenced, so the routine GC never reaps them).
  - After a successful commit the upload dir is removed best-effort — now SAFE, since its refs
    are dangling.
- **B2 — ListMultipartUploads scan is bounded by in-flight uploads (ACCEPTED, documented).**
  `list_multipart_uploads` reads the candidate `arriving/{uuid}/` dirs before truncating to the
  requested cap. The cost is bounded by the number of IN-FLIGHT uploads — operator-controlled
  (every scanned dir is a live CreateMultipartUpload not yet Completed/Aborted/GC'd), exactly
  analogous to the accepted whole-bucket `list_objects` walk that is bounded by live-object
  count (§7.2). To keep a pathological `arriving/` from forcing an unbounded readdir, the scan
  stops after a generous hard cap of `MAX_UPLOADS_CAP * 4` candidate dirs and sets
  `is_truncated`. This is an accepted, documented limitation, not a blocker.
- **B3 — ListObjectsV2 prefix walk-root is sanitized (traversal/DoS fix, IMPLEMENTED).** The
  client `prefix` is a FILTER, never a path. `prefix_walk_root` now sanitizes the prefix's
  dir-portion: any `..`/`.`/empty segment, or an absolute dir-portion, DROPS the subtree-prune
  optimization and roots the walk at `current/`. The existing per-key `starts_with(prefix)`
  filter then matches nothing for such an escaping prefix (no 400). Clean prefixes still prune.
- **B4 — UploadPart propagates the `parts/` dir-fsync error (IMPLEMENTED).** Under `--fsync`,
  a failed `parts/`-dir fsync is now propagated (not swallowed) and the just-written part ref +
  blob are rolled back, so an ACKed part is never left with a non-durable dir entry.
- **B5 — Reclaim keeps the journal on a genuine unlink error (blob-leak fix, IMPLEMENTED).**
  `publish`, `delete_object`, and `apply_journal` now remove the reclaim journal ONLY when every
  reclaim succeeded (Ok, including the missing/invalid no-op). A real unlink error (e.g. EIO)
  leaves the journal in place so `recover()` retries the reclaim (the §3.2 nonce / "K absent"
  rules keep the retry safe), instead of dropping the journal and leaking the blob.

---

## 14. Phased implementation plan (dispatchable to coders)

Each phase ends GREEN: `cargo build`, `cargo clippy`, and the phase's tests pass with
`--race`-equivalent (Rust: run under `cargo test` + targeted concurrency tests; Miri where
already used). Phases are ordered so each builds on a green predecessor.

### Phase 1 — Blob store + manifest format + paths
- **Deliverable:** `blob.rs` (`blob_path`, `write_blob` via DioFile+one-pass-MD5 returning
  `(blob_id, size, md5)`, `open_blob`), `manifest.rs` (`Manifest`, `PartRef{blob_id,…}`,
  read/write/atomic-commit via temp+rename+fsync — port `commit_metadata_temp`/
  `write_metadata_temp_durable` to manifests), the bucket infra-dir creation, key↔path
  escaping (`.meta` reserved-suffix, §7.3).
- **Gate:** unit tests for blob round-trip (small + 50 MB streaming), fanout path
  correctness, manifest JSON round-trip incl. optional fields + parts list, `.meta`
  escape for keys ending in `.meta` and nested `a/b.meta`.

### Phase 2 — Commit & journal protocol + DELETE
- **Deliverable:** the §3 PUBLISH sequence as a reusable internal helper, the §4 DELETE
  sequence, the journal type + write/fsync, the per-key WRITE-lock integration. Wire
  `put_object` (single blob → PUBLISH) and `delete_object`.
- **Gate:** unit tests for fresh PUT, overwrite PUT (old blobs reclaimed, new live), DELETE
  (idempotent, blobs reclaimed), and **fault-injection tests** forcing a failure at each
  protocol step (reuse today's thread-local `force_*_fail` pattern) asserting the §3.1 table
  outcome (old fully live on pre-commit fail; new live + journal present on post-commit fail).

### Phase 3 — GET / HEAD (reader on blobs)
- **Deliverable:** `BlobChainReader` (refactor `MultipartReader` onto blob_id),
  single-blob `PlainFileReader` fast path, `get_object` (snapshot manifest read → resolve
  range → open blobs), `head_object`. `GetObjectResult`/`ObjectMetadata` derivation.
- **Gate:** PUT→GET round trip (small, 50 MB), Range/206/416, missing-blob→error-not-truncate
  (port `multipart_missing_part_errors_not_truncates`), metadata/headers round-trip.

### Phase 4 — Multipart (Create / UploadPart / Complete / Abort / ListParts / ListMPU)
- **Deliverable:** `arriving/{uuid}/` upload dir + `upload.json`; UploadPart → part blob +
  `parts/{NNNNN}.ref`; Complete → validate refs, build manifest, single PUBLISH; Abort →
  delete part blobs + remove upload dir; ListParts / ListMultipartUploads.
- **Gate:** create→3 parts→complete round trip + composite-ETag format; abort cleanup; part
  re-upload (new blob_id) then complete uses latest; concurrent UploadPart-vs-Complete test
  (proves E3-class TOCTOU is structurally gone); wrong-ETag / empty-parts / bad-order errors.

### Phase 5 — ListObjectsV2 on the manifest tree
- **Deliverable:** `list_objects` walking `current/`, decode `.meta`→key, prefix/delimiter/
  sort/paginate reusing today's algorithm; `list_buckets`/`delete_bucket` "empty" semantics
  vs the 4 infra dirs.
- **Gate:** port the existing list tests (prefix, delimiter→CommonPrefixes, max-keys absent
  vs Some(0) F14, continuation-token = last-emitted C6, start-after, empty bucket); flat +
  nested keys; reserved `.meta` key listed correctly.

### Phase 6 — Crash-recovery sweep + `recover()` + main wiring
- **Deliverable:** §6 SWEEP (6.1 arriving, 6.2 journals w/ nonce rule, 6.3 fallback GC),
  `Filesystem::recover()`, call it in `main.rs` before bind, optional periodic timer
  (6.1+6.2, GRACE) behind a flag (default off / startup-only).
- **Gate:** NEW crash-recovery tests: simulate each crash row of §3.1/§4 (leave artifacts on
  disk, run `recover()`, assert correct live version + no orphans + idempotent re-run);
  fallback-GC reclaims a lost-journal orphan and never deletes a referenced blob.

### Phase 7 — Concurrency hardening tests
- **Deliverable:** no new prod code expected (locking landed in Phases 2/4); this phase is the
  **concurrent-overwrite-during-GET** proof and same-key race coverage.
- **Gate:** test that starts a long GET (reading old blobs), runs a same-key overwrite to
  completion (new blobs + manifest swap + reclaim of old blobs), and asserts the GET either
  (a) completes with the OLD bytes (fd pinned) or (b) fails fast with truncation — **never
  mixed bytes**. Concurrent same-key PUT/PUT, PUT/Delete, Complete/Delete serialization tests.

### Phase 8 — Integration gate (the contract proof)
- **Deliverable:** none (no code) — run the existing end-to-end suites against the rewritten
  storage.
- **Gate:** `scripts/smoke.sh` **19/19 PASS**; `cargo test --test server_e2e` (all 7 e2e fns)
  pass; full `cargo test` (all ~78 unaffected unit tests + the rewritten storage tests) green;
  `cargo clippy` clean. README/DESIGN updated to describe the content-addressed layout and the
  clean-break (no-migration) note.

---

## 15. Diagram — publish at a glance

```
        PUT key=K  (new body)
            │  write body -> blobs/ab/cd/{NEW_BLOB}  (one-pass MD5, fsync)   [lock-free]
            │
            ▼  ── per-key WRITE lock ──────────────────────────────────────────────┐
  1  arriving/{u}.meta  = manifest{parts:[{NEW_BLOB,…}], commit_nonce:N}  (fsync)   │
  2  deleted/{j}.journal = {supersedes:K, commit_nonce:N, blobs:[OLD_BLOB…]}(fsync) │  (only if K existed)
  3  rename arriving/{u}.meta ─────────► current/K.meta      ◄── ATOMIC COMMIT      │
            │                                                                        │
  4  delete blobs[OLD_BLOB…]                                                         │
  5  delete deleted/{j}.journal                                                      │
            └────────────────────────────────────────────────────────────────────┘
                         crash anywhere ⇒ §3.1 table ⇒ recover() fixes it
```

Concurrent GET of K during the above: reads `current/K.meta` (old or new, atomically),
opens the blobs it names. OLD_BLOB is alive until step 4; if step 4 unlinks it while an
old-manifest GET hasn't opened it yet → ENOENT → truncate. **Never mixed bytes.**
