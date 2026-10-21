# RevKit

RevKit is a small, reproducible reverse-engineering workstation bootstrap for Debian and Ubuntu x86-64.

It installs a curated set of tools through the system APT repositories and official upstream GitHub releases. The Go CLI keeps the tool catalog, checks installation state, generates a local dashboard, and writes static triage reports.

## Why RevKit

A normal workstation can be a useful place to learn binary analysis when its tools and workspace are organized. RevKit provides a repeatable starting point without replacing the operating system's package manager or turning into a general-purpose framework.

RevKit is **not** a Kali or REMnux replacement, a malware sandbox, or an automated challenge solver. It does not execute targets during triage.

## Tools

The catalog covers ELF inspection, debugging, compilation, disassembly, hex editing, Python analysis libraries, firmware inspection, and static analysis. It includes `file`, GNU binutils, elfutils, checksec, GDB, GDB multiarch, LLDB, strace, ltrace, Valgrind, QEMU user mode, GCC, Clang, LLVM, NASM, Yasm, Python 3, pyelftools, Capstone, YARA, radare2, and Binwalk.

The official standalone releases are Ghidra, Cutter, Pwndbg, Mandiant FLOSS, and capa. RevKit checks the host architecture, selects a matching release asset, requires its SHA-256 digest, and verifies executable architecture before replacing a managed installation. A release without a verified x86-64 asset is refused.

## Install

Requirements: Debian or Ubuntu on x86-64, a working APT configuration, and Go 1.18 or newer. If Go is missing, the bootstrap installs `golang-go` from the configured Debian or Ubuntu repositories.

The bootstrap uses its own location to find the source and defaults to `~/Desktop/RevKit`, regardless of the current directory:

```sh
git clone https://github.com/Voldigoade/revkit.git
cd revkit
./install.sh
```

Choose a different root with `--root`:

```sh
./install.sh --root "$HOME/Tools/RevKit"
```

Preview the package and release actions without changing the root, PATH, or shell profile:

```sh
./install.sh --root "$HOME/Tools/RevKit" --dry-run
```

APT changes require administrator access. RevKit only asks APT to install or update packages in its catalog; it does not run a system-wide upgrade. Packages missing from the configured repositories are reported and skipped, and standalone tools that need them are left uninstalled. Standalone releases are kept under the selected root.

## Commands

```text
revkit install [--dry-run]    Install missing tools and repair broken installs
revkit update [--dry-run]     Refresh APT metadata and update managed tools
revkit doctor                 Check the root, tools, launchers, versions, and architecture
revkit list                   List catalog tools and local status
revkit triage FILE            Write a static-only report
revkit dashboard [--dry-run]  Generate and open the local dashboard
revkit uninstall [--dry-run]  Remove RevKit files and standalone tools
```

The chosen root is recorded in `state.json` and inferred from the installed CLI. To use an alternate root for one command, put `--root PATH` before the command:

```sh
revkit --root "$HOME/Tools/RevKit" doctor
```

`install` checks APT package state and rechecks upstream releases at most once every seven days. `update` refreshes APT metadata and checks upstream releases immediately. Repeating either command does not reinstall current tools. `uninstall` preserves `workspace/` and leaves APT packages installed because other software may depend on them.

## Learning workflow

Use the dashboard to move from a question to evidence:

```text
Identify → Inspect structure → Find clues → Static analysis → Dynamic analysis → Verify hypothesis
```

Search for `[object] + [wanted action] + [context]`. For example: `ELF inspect sections readelf` or `x86 debugger registers beginner`. Start with `man TOOL`, `TOOL --help`, and official documentation. Keep observations separate from conclusions.

`revkit triage FILE` records the file path, metadata, SHA-256, and available `file`, `checksec`, `readelf`, and `strings` output in `workspace/reports/`. The report states that the target was **not executed**. Dynamic analysis is outside this command; use an isolated lab when execution is required.

## Layout

The source repository contains the CLI, catalog, templates, and educational examples. After installation, the selected root contains:

```text
RevKit/
├── bin/revkit
├── tools/gui/
├── tools/cli/
├── workspace/
│   ├── samples/
│   ├── reports/
│   └── notes/
├── dashboard/index.html
└── state.json
```

APT-managed tools remain in normal system locations such as `/usr/bin`; RevKit does not copy them into this tree. Existing files in `workspace/samples` are never overwritten.

## Supported systems

V1 supports Debian and Ubuntu on x86-64 (`amd64`). Other distributions, macOS, Windows, ARM, and other CPU architectures are not supported.

Ghidra requires Java 21. Its APT package must be available from the enabled Debian or Ubuntu repositories. Cutter is distributed as an AppImage and depends on the host's AppImage support.

## Safety

Reverse-engineering tools can run untrusted code when asked to debug, emulate, or extract it. RevKit's triage command only reads the target and invokes analysis utilities; it never starts the target process. This does not make other tool use safe. Use disposable, isolated environments for dynamic analysis and firmware extraction.

RevKit downloads standalone assets only from the official GitHub repository listed in the manifest. It validates the release digest and archive paths, and refuses incompatible architectures. A digest confirms the downloaded bytes match the digest published by that release; it is not a code audit.

## Development

```sh
go test ./...
go vet ./...
```

The code uses the Go standard library only. The test suite covers the manifest, architecture selection, version and installation state, path handling, dashboard rendering, static triage, archive safety, and doctor checks.

## Contributing

Keep changes small and specific to Debian or Ubuntu x86-64 V1. Add tool metadata to `internal/catalog/manifest.json` rather than duplicating descriptions in the CLI or dashboard. Include tests for state changes, path handling, and architecture selection.

## License

MIT. See [LICENSE](LICENSE).
