# Coredumps (issue #382)

When the firmware panics, IDF's panic handler writes an ELF coredump to the
`coredump` flash partition, then the board reboots as usual. The dump survives
the reboot, so a panic that nobody was watching on serial can still be
diagnosed afterwards. Before #382 every panic was a one-shot: if no serial
reader was attached, it was gone (#370's only panic was lost that way).

## Is there a dump?

`GET /api/status` (no login needed) carries:

```json
"coredump": {"present": true, "size": 45184}
```

`present` means the partition holds a dump with a plausible size **and** the
ELF magic where a real one has it. Stale bytes from an older partition layout
are not reported as a dump.

## Read it back over HTTP

No esptool needed. That matters on `.244`, where esptool's resets can park the
board in ROM download mode (#338).

```sh
B=http://192.168.12.244
curl -s -c jar -d 'username=<user>&password=<pass>' $B/api/admin/login
curl -s -b jar $B/api/coredump/info
curl -s -b jar -o core.bin $B/api/coredump
```

| Route | Gate | Returns |
|---|---|---|
| `GET /api/coredump/info` | admin session | `task`, `pc`, `elfSha`, `reason`, and `valid` (stored checksum verified) |
| `GET /api/coredump` | **owner** session (a sysop passes while no owner account exists, as with every #173 owner action) | the raw flash image, `application/octet-stream` |
| `POST /api/coredump/erase` | admin session + `X-CSRF` | `{"erased":true}` |

The download is owner-gated because a dump is a copy of task stacks at the
moment of the panic, and a stack can hold a digest secret, an OAuth token or a
TLS session key. Treat `core.bin` accordingly.

Only the latest panic is kept: a new panic overwrites the previous dump.

## Decode it

You need the **exact ELF** of the firmware that panicked. `info` reports its
SHA-256 prefix as `elfSha`, and it must match
`sha256sum SipServer.elf` of your candidate, or the symbols are fiction:

```sh
esp-coredump --chip esp32s3 info_corefile -t raw -c core.bin build/SipServer.elf
```

That prints the crashed task, the exception cause, a symbolised backtrace for
every task, and the registers. `dbg_corefile` opens the same dump in GDB.

Keep the ELF of anything you flash to a bench board; the dump outlives the
build directory it came from.

## Partition layout

| Table | coredump | Notes |
|---|---|---|
| `partitions.csv` (16 MB) | `0xC20000`, 128 KB | taken from the front of `prompts`, which moved to `0xC40000` (nothing reads `prompts` yet) |
| `partitions_4mb.csv` | `0x3E0000`, 128 KB | the space already free at the top |

**Sized from a measurement.** An induced panic in a PSRAM-stacked task on `.244`
(idle, anchor connected) produced a **45,184-byte** dump: 25 tasks at about
720 bytes each (TCB plus register note) plus 25.4 KB of live stacks. A panic
mid-call adds the media and anchor tasks and deep TLS stacks. A dump larger
than the partition is **not truncated, it is abandoned whole** ("Not enough
space to save core dump!" on UART only), so the 56 KB first choice was too
tight.

**Getting the partition onto a board.** OTA never rewrites the partition
table, so a board only gains the partition from a full USB flash (bootloader,
partition table and app). A board without it simply has no coredumps; that is
not an error. When a board does get the new table, erase the region once:

```sh
esptool --chip esp32s3 --port <port> erase-region 0xC20000 0x20000
```

`.244` held stale non-`0xFF` data in the region its first layout used. The
firmware rejects such data (no ELF magic), but erased flash is the clean state.

## Configuration

One line in `sdkconfig.defaults`: `CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH=y`.
IDF 6 fixes the format at ELF with a SHA-256 checksum. PSRAM task stacks are
captured (IDF's Kconfig help text saying otherwise is stale). Measured cost:
**+4,044 bytes of static internal RAM**, part of it the dump's own 1,792-byte
DRAM stack.
