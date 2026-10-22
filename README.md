# RevKit

RevKit turns a Debian-family x86-64 workstation into a small, reproducible environment for learning static reverse engineering.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/Voldigoade/revkit/main/install.sh | sh
```

To inspect the bootstrap first:

```sh
curl -fsSLO https://raw.githubusercontent.com/Voldigoade/revkit/main/install.sh
less install.sh
sh install.sh
```

The installer verifies the official Linux x86-64 release checksum before installing `~/.local/bin/revkit`. It then initializes the workstation. Use `--root "$HOME/Tools/RevKit"` to choose a different data directory. The default is the user's XDG Desktop directory, including localized names such as `Bureau`, followed by `~/Desktop/RevKit` as a fallback. Add `~/.local/bin` to `PATH` if your shell does not already include it.

## Quick start

```sh
revkit
revkit analyze ./sample --json
revkit dashboard
```

With an interactive terminal, `revkit` opens a small keyboard-driven menu. Choose **Analyze a file**, select a sample, then open **Reports** or the dashboard. In scripts, use `revkit analyze FILE --json`; the CLI does not require the TUI.

Analysis is offline and static. It writes Markdown, JSON, and HTML under `workspace/reports/`. The report explains the detected format and architecture, highlights evidence, and suggests focused next steps and search terms. The dashboard regenerates after each analysis and links to reports with ordinary local HTML links.

## Commands

```text
revkit install [--dry-run]   Install missing or repair broken managed tools
revkit update [--dry-run]    Update RevKit and managed tools that need it
revkit doctor [--json]       Check the host, installation, and tool state
revkit list [--json]         List tools and their current state
revkit analyze FILE [--json] Analyze without executing the target
revkit dashboard             Regenerate and open the local dashboard
revkit version               Print the release version and commit
revkit uninstall [--dry-run] Remove the RevKit executable and managed tools
```

Choose a data directory with `revkit --root "$HOME/Tools/RevKit" COMMAND`. The choice is remembered for later runs. `uninstall` leaves workspace data and APT packages in place.

## What it manages

The catalog combines core system tools from configured APT repositories with optional tools. Core checks determine whether the RevKit installation is usable. Missing optional packages are reported as warnings and do not make the installation fail. RevKit never performs an unrestricted system upgrade.

The curated catalog includes file, GNU binutils and elfutils, checksec, GDB, LLDB, strace, ltrace, Valgrind, QEMU user mode, GCC, Clang/LLVM, NASM/Yasm, Python analysis libraries, YARA, radare2, Binwalk, Ghidra, Cutter, Pwndbg, Mandiant FLOSS, capa, and Detect It Easy. Standalone applications are downloaded only from their official upstream release pages and verified before use. Some optional tools may not be available in every APT repository.

## Supported systems

RevKit targets Linux x86-64 (`amd64`) with a Debian-family APT environment. CI tests Ubuntu 24.04 and Debian stable. Debian/Ubuntu derivatives whose `ID_LIKE` identifies Debian or Ubuntu are best effort; package names and availability can differ. Other distributions, CPU architectures, macOS, and Windows are not supported.

## Safety

RevKit is not a Kali or REMnux replacement, a malware sandbox, or a challenge solver. `analyze` never starts the target, invokes Wine, or extracts archives. It uses bounded static parsers and tools with timeouts and output limits. Automatic capa and FLOSS analysis is skipped when their version cannot be confirmed or predates the upstream workspace-loading fix. This does not make later debugging, emulation, or extraction safe; use an isolated environment for dynamic work. A release checksum checks downloaded bytes against the published digest, but it is not a code audit.

## Workstation layout

```text
RevKit/
├── tools/gui/                 Standalone graphical tools
├── tools/cli/                 Standalone command-line tools
├── workspace/samples/         Learning examples
├── workspace/reports/         Markdown, JSON, and HTML analysis reports
├── workspace/notes/           User notes
├── dashboard/index.html       Static dashboard
└── state.json                 Managed tool state
```

The RevKit executable lives in `~/.local/bin/revkit`; APT tools stay in system locations such as `/usr/bin`.

## Development

Building from source requires Go 1.25.0 or newer. CI uses the current patched Go release. Format and verify with:

```sh
gofmt -w $(rg --files -g '*.go')
go test ./...
go test -race ./...
go vet ./...
```

CI also runs Staticcheck, govulncheck, ShellCheck, the bootstrap checks, and the tracked-text punctuation check. Keep changes focused and add tests for behavior that affects installation, analysis, reports, or platform detection.

## License

MIT. See [LICENSE](LICENSE).
