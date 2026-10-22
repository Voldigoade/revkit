package analyze

import (
	"bufio"
	"context"
	"crypto/sha256"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"archive/zip"

	"github.com/Voldigoade/revkit/internal/report"
	"github.com/Voldigoade/revkit/internal/state"
)

const (
	defaultMaxFileSize = 128 << 20
	maxEvidenceOutput  = 128 << 10
	maxSummaryScan     = 1 << 20
)

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type Analyzer struct {
	Root        string
	Runner      Runner
	LookPath    func(string) (string, error)
	MaxFileSize int64
}

type CommandRunner struct {
	Timeout   time.Duration
	MaxOutput int
}

type outputBuffer struct {
	sync.Mutex
	data    []byte
	maximum int
	limited bool
}

func (b *outputBuffer) Write(data []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	original := len(data)
	remaining := b.maximum - len(b.data)
	if remaining <= 0 {
		b.limited = true
		return original, nil
	}
	if len(data) > remaining {
		data = data[:remaining]
		b.limited = true
	}
	b.data = append(b.data, data...)
	return original, nil
}

func (b *outputBuffer) snapshot() ([]byte, bool) {
	b.Lock()
	defer b.Unlock()
	return append([]byte(nil), b.data...), b.limited
}

func (r CommandRunner) Run(parent context.Context, executable string, args ...string) ([]byte, error) {
	if r.Timeout <= 0 {
		r.Timeout = 12 * time.Second
	}
	if r.MaxOutput <= 0 {
		r.MaxOutput = maxEvidenceOutput
	}
	ctx, cancel := context.WithTimeout(parent, r.Timeout)
	defer cancel()
	command := exec.CommandContext(ctx, executable, args...)
	command.Stdin = nil
	command.Env = workspaceSafeEnvironment()
	output := &outputBuffer{maximum: r.MaxOutput}
	command.Stdout, command.Stderr = output, output
	err := command.Run()
	data, limited := output.snapshot()
	if limited {
		return data, errors.New("analyzer output limit reached")
	}
	if ctx.Err() != nil {
		return data, ctx.Err()
	}
	return data, err
}

func (a Analyzer) Analyze(ctx context.Context, inputPath string) (result report.Report, err error) {
	path, err := filepath.Abs(inputPath)
	if err != nil {
		return result, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return result, fmt.Errorf("inspect input: %w", err)
	}
	if !info.Mode().IsRegular() {
		return result, errors.New("input must be a regular file")
	}
	limit := a.MaxFileSize
	if limit <= 0 {
		limit = defaultMaxFileSize
	}
	if info.Size() > limit {
		return result, fmt.Errorf("input exceeds the %d-byte size limit", limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return result, fmt.Errorf("open input: %w", err)
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		return result, fmt.Errorf("inspect open input: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return result, errors.New("input changed or is not a regular file")
	}
	hash := sha256.New()
	read, err := io.Copy(hash, io.LimitReader(file, limit+1))
	if err != nil {
		return result, fmt.Errorf("hash input: %w", err)
	}
	if read > limit {
		return result, fmt.Errorf("input exceeds the %d-byte size limit", limit)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return result, err
	}
	result = report.Report{
		SchemaVersion: 1,
		Metadata: report.Metadata{
			Name: filepath.Base(path), Path: path, Size: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil)), Modified: info.ModTime().UTC(), CreatedAt: time.Now().UTC(),
		},
		Identification: report.Identification{Format: "unknown binary", Architecture: "unknown"},
	}
	result, err = a.inspect(ctx, file, info.Size(), result)
	if err != nil {
		return result, err
	}
	result.Explanation = explain(result.Identification)
	return result, nil
}

func explain(id report.Identification) string {
	switch id.Format {
	case "ELF":
		if id.Class == "malformed" {
			return "The file has an ELF signature, but its headers could not be parsed. Its architecture and executable type are not confirmed."
		}
		bits := ""
		if id.Class == "ELF32" {
			bits = "32-bit "
		} else if id.Class == "ELF64" {
			bits = "64-bit "
		}
		return fmt.Sprintf("This is a %sELF file for %s. ELF is commonly used by Linux programs; its headers describe how the loader and analysis tools interpret it.", bits, architectureMeaning(id.Architecture))
	case "PE":
		if id.Class == "malformed" {
			return "The file has a Windows executable signature, but its PE headers could not be parsed. Its architecture and subsystem are not confirmed."
		}
		bits := ""
		if id.Class == "PE32" {
			bits = "32-bit"
		} else if id.Class == "PE32+" {
			bits = "64-bit"
		}
		return fmt.Sprintf("PE is the standard Windows executable format. This is a %s program for %s using the %s subsystem.", bits, architectureMeaning(id.Architecture), id.Subsystem)
	case "ZIP archive":
		return "This file is a container for named entries. RevKit only read the archive directory; it did not extract or run any contents."
	case "text/script":
		return "This file is readable text or a script, not a recognized compiled executable. Read it as source; RevKit did not run it."
	default:
		return "The file did not match the supported executable, archive, or text formats. Its architecture is unknown; the header preview and hash are safe starting points."
	}
}

func architectureMeaning(architecture string) string {
	switch architecture {
	case "x86-64":
		return "x86-64, the 64-bit extension of x86"
	case "x86":
		return "x86, the 32-bit Intel-compatible instruction set"
	case "AArch64":
		return "AArch64, the 64-bit ARM instruction set"
	case "ARM":
		return "ARM, a 32-bit ARM instruction set"
	case "unknown", "":
		return "an unknown processor architecture"
	default:
		return architecture
	}
}

func (a Analyzer) inspect(ctx context.Context, file *os.File, size int64, result report.Report) (report.Report, error) {
	header := make([]byte, 4096)
	count, err := file.ReadAt(header, 0)
	if err != nil && err != io.EOF {
		return result, fmt.Errorf("read file header: %w", err)
	}
	header = header[:count]
	switch {
	case len(header) >= 4 && string(header[:4]) == "\x7fELF":
		a.inspectELF(file, size, &result)
	case len(header) >= 2 && string(header[:2]) == "MZ":
		a.inspectPE(file, size, &result)
	case isZIPHeader(header):
		a.inspectZIP(file, size, &result)
	case isText(header):
		a.inspectText(file, size, header, &result)
	default:
		a.inspectGeneric(file, size, header, &result)
	}
	if (result.Identification.Format == "ELF" || result.Identification.Format == "PE") && result.Identification.Class != "malformed" {
		a.addFormatTools(ctx, file.Name(), result.Metadata.Size, result.Identification.Format, &result)
	}
	return result, nil
}

func (a Analyzer) inspectELF(file *os.File, size int64, result *report.Report) {
	result.Identification.Format = "ELF"
	parsed, err := parseELF(file)
	if err != nil {
		result.Identification.Class = "malformed"
		result.Summary = "ELF signature found, but its headers could not be read."
		result.Warnings = append(result.Warnings, "ELF header parsing failed: "+err.Error())
		result.NextSteps = headerNextSteps()
		addStringEvidence(collectStrings(file, size), result)
		return
	}
	result.Identification.Class = parsed.class
	result.Identification.Architecture = parsed.architecture
	result.Identification.Endianness = parsed.endianness
	if parsed.dynamic {
		linking := "dynamically linked"
		if parsed.pie {
			linking += " position-independent executable"
		}
		result.Findings = append(result.Findings, report.Finding{Title: "Dynamic linking", Meaning: linking + ".", Why: "The program depends on a runtime loader and shared libraries; those dependencies help explain its behavior and environment.", Evidence: []string{parsed.interpreter}})
	} else {
		result.Findings = append(result.Findings, report.Finding{Title: "No dynamic interpreter", Meaning: "No ELF interpreter segment was found.", Why: "This is consistent with a static executable or a non-executable shared object; confirm the ELF type before drawing a conclusion.", Evidence: []string{"PT_INTERP: absent"}})
	}
	stripped := !parsed.symbols
	if stripped {
		result.Findings = append(result.Findings, report.Finding{Title: "Symbol table absent", Meaning: "The usual ELF symbol table is not present.", Why: "Function names may be missing in a disassembler, so strings and cross-references can provide useful navigation clues.", Evidence: []string{".symtab: absent"}})
	} else {
		result.Findings = append(result.Findings, report.Finding{Title: "Symbols present", Meaning: "The ELF symbol table is present.", Why: "Function and object names may make initial navigation easier.", Evidence: []string{".symtab: present"}})
	}
	debugText := "absent"
	if parsed.debugInfo {
		debugText = "present"
	}
	result.Findings = append(result.Findings, report.Finding{Title: "Debug information", Meaning: "Debug information is " + debugText + ".", Why: "Debug data can preserve source locations and names, which helps connect machine code to the original program structure.", Evidence: []string{".debug_info: " + debugText}})
	if parsed.nx {
		result.Findings = append(result.Findings, report.Finding{Title: "Non-executable stack", Meaning: "The program requests a non-executable stack.", Why: "This protection makes code on the stack non-executable on supporting systems.", Evidence: []string{"PT_GNU_STACK: non-executable"}})
	} else {
		result.Warnings = append(result.Warnings, "A non-executable stack was not confirmed from the program headers.")
	}
	if parsed.relro {
		result.Findings = append(result.Findings, report.Finding{Title: "RELRO segment", Meaning: "A GNU RELRO segment is present.", Why: "RELRO protects selected relocation data after the dynamic loader has finished using it.", Evidence: []string{"PT_GNU_RELRO: present"}})
	}
	result.Evidence = append(result.Evidence, report.Evidence{Source: "ELF header", Output: fmt.Sprintf("Class: %s\nArchitecture: %s\nEndianness: %s\nType: %s\nSections: %s", parsed.class, parsed.architecture, parsed.endianness, parsed.fileType, strings.Join(parsed.sections, ", "))})
	result.Summary = fmt.Sprintf("%s %s ELF %s.", parsed.class, parsed.architecture, strings.ToLower(parsed.fileType))
	result.NextSteps = elfNextSteps()
	if parsed.pie {
		result.Summary = fmt.Sprintf("Position-independent %s %s ELF executable.", parsed.class, parsed.architecture)
	}
	addStringEvidence(collectStrings(file, size), result)
}

type elfInfo struct {
	class        string
	architecture string
	endianness   string
	fileType     string
	dynamic      bool
	pie          bool
	interpreter  string
	symbols      bool
	debugInfo    bool
	nx           bool
	relro        bool
	sections     []string
}

func parseELF(reader io.ReaderAt) (info elfInfo, err error) {
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("ELF parser rejected malformed data")
		}
	}()
	file, err := elf.NewFile(reader)
	if err != nil {
		return info, err
	}
	defer file.Close()
	info.class = map[elf.Class]string{elf.ELFCLASS32: "ELF32", elf.ELFCLASS64: "ELF64"}[file.Class]
	if info.class == "" {
		info.class = "unknown ELF class"
	}
	info.architecture = elfArchitecture(file.Machine)
	info.endianness = "big-endian"
	if file.ByteOrder == binary.LittleEndian {
		info.endianness = "little-endian"
	}
	info.fileType = file.Type.String()
	info.symbols = hasSection(file, ".symtab")
	info.debugInfo = hasSection(file, ".debug_info") || hasSection(file, ".zdebug_info")
	info.nx = false
	for _, program := range file.Progs {
		switch program.Type {
		case elf.PT_INTERP:
			info.dynamic = true
			if data, readErr := io.ReadAll(io.LimitReader(program.Open(), 4096)); readErr == nil {
				info.interpreter = strings.TrimRight(string(data), "\x00")
			}
		case elf.PT_GNU_STACK:
			info.nx = program.Flags&elf.PF_X == 0
		case elf.PT_GNU_RELRO:
			info.relro = true
		}
	}
	info.pie = info.dynamic && file.Type == elf.ET_DYN
	for _, section := range file.Sections {
		info.sections = append(info.sections, section.Name)
	}
	return info, nil
}

func hasSection(file *elf.File, name string) bool {
	for _, section := range file.Sections {
		if section.Name == name {
			return true
		}
	}
	return false
}

func elfArchitecture(machine elf.Machine) string {
	switch machine {
	case elf.EM_X86_64:
		return "x86-64"
	case elf.EM_386:
		return "x86"
	case elf.EM_AARCH64:
		return "AArch64"
	case elf.EM_ARM:
		return "ARM"
	case elf.EM_MIPS:
		return "MIPS"
	case elf.EM_RISCV:
		return "RISC-V"
	default:
		return machine.String()
	}
}

func (a Analyzer) inspectPE(file *os.File, size int64, result *report.Report) {
	result.Identification.Format = "PE"
	parsed, err := parsePE(file)
	if err != nil {
		result.Identification.Class = "malformed"
		result.Summary = "Windows executable signature found, but its PE headers could not be read."
		result.Warnings = append(result.Warnings, "PE header parsing failed: "+err.Error())
		result.NextSteps = headerNextSteps()
		addStringEvidence(collectStrings(file, size), result)
		return
	}
	result.Identification.Class = parsed.class
	result.Identification.Architecture = parsed.architecture
	result.Identification.Subsystem = parsed.subsystem
	if parsed.debugInfo {
		result.Findings = append(result.Findings, report.Finding{Title: "Debug data", Meaning: "A PE debug data directory is present.", Why: "Debug data may preserve source or build information that helps explain the program.", Evidence: []string{"IMAGE_DIRECTORY_ENTRY_DEBUG: present"}})
	} else {
		result.Findings = append(result.Findings, report.Finding{Title: "Debug data not found", Meaning: "The PE debug data directory is absent.", Why: "Source-level names and line information may not be available, so start from imports, strings, and code references.", Evidence: []string{"IMAGE_DIRECTORY_ENTRY_DEBUG: absent"}})
	}
	if parsed.stripped {
		result.Findings = append(result.Findings, report.Finding{Title: "Debug symbols stripped", Meaning: "The PE header marks debug symbols as stripped.", Why: "Named symbols may be limited; strings and imports can still provide navigation clues.", Evidence: []string{"IMAGE_FILE_DEBUG_STRIPPED: set"}})
	}
	if len(parsed.imports) > 0 {
		result.Findings = append(result.Findings, report.Finding{Title: "Imported functions", Meaning: "The import table references external Windows functions.", Why: "Imports can reveal broad dependencies and suggest code paths to inspect.", Evidence: parsed.imports})
	}
	result.Evidence = append(result.Evidence, report.Evidence{Source: "PE header", Output: fmt.Sprintf("Class: %s\nArchitecture: %s\nSubsystem: %s\nSections: %s\nDebug data: %s", parsed.class, parsed.architecture, parsed.subsystem, strings.Join(parsed.sections, ", "), yesNo(parsed.debugInfo))})
	result.Summary = fmt.Sprintf("%s Windows PE %s executable.", parsed.class, strings.ToLower(parsed.subsystem))
	result.NextSteps = peNextSteps()
	addStringEvidence(collectStrings(file, size), result)
}

type peInfo struct {
	class        string
	architecture string
	subsystem    string
	debugInfo    bool
	stripped     bool
	sections     []string
	imports      []string
}

func parsePE(reader io.ReaderAt) (info peInfo, err error) {
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("PE parser rejected malformed data")
		}
	}()
	file, err := pe.NewFile(reader)
	if err != nil {
		return info, err
	}
	defer file.Close()
	info.architecture = peArchitecture(file.Machine)
	info.stripped = file.Characteristics&0x0200 != 0
	info.subsystem = "unknown subsystem"
	switch optional := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		info.class = "PE32"
		info.subsystem = peSubsystem(optional.Subsystem)
		info.debugInfo = optional.DataDirectory[6].VirtualAddress != 0
	case *pe.OptionalHeader64:
		info.class = "PE32+"
		info.subsystem = peSubsystem(optional.Subsystem)
		info.debugInfo = optional.DataDirectory[6].VirtualAddress != 0
	default:
		return info, errors.New("unsupported PE optional header")
	}
	for _, section := range file.Sections {
		info.sections = append(info.sections, section.Name)
	}
	imports, importErr := file.ImportedSymbols()
	if importErr == nil {
		info.imports = append(info.imports, imports...)
	}
	return info, nil
}

func peArchitecture(machine uint16) string {
	switch machine {
	case 0x014c:
		return "x86"
	case 0x8664:
		return "x86-64"
	case 0x01c4:
		return "ARM"
	case 0xaa64:
		return "AArch64"
	default:
		return fmt.Sprintf("machine 0x%04x", machine)
	}
}

func peSubsystem(value uint16) string {
	switch value {
	case 2:
		return "Windows GUI"
	case 3:
		return "Windows console"
	case 1:
		return "native Windows"
	case 10:
		return "EFI application"
	default:
		return fmt.Sprintf("subsystem %d", value)
	}
}

func (a Analyzer) inspectZIP(file *os.File, size int64, result *report.Report) {
	result.Identification.Format = "ZIP archive"
	result.Identification.Architecture = "n/a"
	archive, err := zip.NewReader(file, size)
	if err != nil {
		result.Summary = "ZIP archive signature found, but its directory could not be read."
		result.Warnings = append(result.Warnings, "ZIP directory parsing failed: "+err.Error())
	} else {
		var entries []string
		for _, entry := range archive.File {
			name := entry.Name
			cleanName := pathpkg.Clean(strings.ReplaceAll(name, "\\", "/"))
			if pathpkg.IsAbs(cleanName) || cleanName == ".." || strings.HasPrefix(cleanName, "../") {
				result.Warnings = append(result.Warnings, "Archive contains a path that would escape an extraction directory: "+name)
			}
			entries = append(entries, fmt.Sprintf("%s (%d bytes)", name, entry.UncompressedSize64))
		}
		result.Evidence = append(result.Evidence, report.Evidence{Source: "ZIP directory", Output: strings.Join(entries, "\n")})
		result.Summary = fmt.Sprintf("ZIP archive with %d listed entries; RevKit did not extract its contents.", len(archive.File))
		result.Findings = append(result.Findings, report.Finding{Title: "Archive contents", Meaning: "The file contains a ZIP directory with named entries.", Why: "Entry names and sizes can help decide which files are relevant before opening them.", Evidence: entries})
	}
	result.NextSteps = []report.NextStep{{Action: "Use file to confirm the archive type, then analyze a relevant listed file separately. RevKit does not extract archives.", Tool: "file", Learn: []string{"ZIP archive structure", "file signatures"}, Searches: []string{"ZIP local file header format", "Linux file command identify archive"}}}
}

func (a Analyzer) inspectText(file *os.File, size int64, header []byte, result *report.Report) {
	result.Identification.Format = "text/script"
	result.Identification.Architecture = "n/a"
	result.Summary = "Readable text or script, not a recognized compiled executable."
	contents, err := io.ReadAll(io.NewSectionReader(file, 0, size))
	if err != nil {
		result.Warnings = append(result.Warnings, "Text content could not be read completely: "+err.Error())
	}
	result.Evidence = append(result.Evidence, report.Evidence{Source: "Text content", Output: string(contents)})
	if strings.HasPrefix(string(header), "#!") {
		line := strings.SplitN(string(header), "\n", 2)[0]
		result.Findings = append(result.Findings, report.Finding{Title: "Interpreter declaration", Meaning: "The first line declares an interpreter.", Why: "This identifies how the script would be started; RevKit records the line but never runs the script.", Evidence: []string{line}})
	}
	result.NextSteps = []report.NextStep{{Action: "Open the source in less and trace its inputs, branches, and external commands.", Tool: "less", Learn: []string{"shell or scripting language basics", "input validation"}, Searches: []string{"shell script beginner control flow", "Linux script interpreter shebang"}}}
}

func (a Analyzer) inspectGeneric(file *os.File, size int64, header []byte, result *report.Report) {
	result.Identification.Format = "unknown binary"
	result.Identification.Architecture = "unknown"
	preview := header
	if len(preview) > 32 {
		preview = preview[:32]
	}
	result.Evidence = append(result.Evidence, report.Evidence{Source: "Header preview", Output: hex.EncodeToString(preview)})
	result.Summary = "No recognized executable or archive format was found."
	result.Findings = append(result.Findings, report.Finding{Title: "Unknown format", Meaning: "The header does not match the supported ELF, PE, ZIP, or text formats.", Why: "This may be a data file, an uncommon format, or a damaged header; preserve the original and verify its source before using specialized tools.", Evidence: []string{"First bytes: " + hex.EncodeToString(preview)}})
	result.NextSteps = []report.NextStep{{Action: "Compare the header with known file signatures, then inspect a copy with a hex viewer.", Tool: "xxd", Learn: []string{"magic bytes", "hexadecimal byte offsets"}, Searches: []string{"file format magic bytes Linux", "xxd hex viewer beginner"}}}
	addStringEvidence(collectStrings(file, size), result)
}

func (a Analyzer) addFormatTools(ctx context.Context, path string, size int64, format string, result *report.Report) {
	if a.Runner == nil {
		a.Runner = CommandRunner{}
	}
	lookPath := a.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	type tool struct {
		name     string
		execPath string
		args     []string
	}
	var tools []tool
	if format == "ELF" {
		tools = append(tools, tool{name: "readelf", args: []string{"--wide", "-h", "-S", "-l", path}}, tool{name: "checksec", args: []string{"--file=" + path}})
	}
	if size <= 64<<20 {
		if format == "PE" || format == "ELF" {
			for _, item := range []struct {
				name    string
				minimum string
			}{
				{name: "capa", minimum: "10.0.0"},
				{name: "floss", minimum: "3.2.0"},
			} {
				findTool := func(name string) (string, error) { return a.findTool(name, lookPath) }
				executable, warning := verifiedAnalyzer(ctx, a.Runner, findTool, item.name, item.minimum)
				if warning != "" {
					result.Warnings = append(result.Warnings, warning)
				}
				if executable == "" {
					continue
				}
				args := []string{path}
				if item.name == "capa" {
					args = []string{"-q", path}
				}
				tools = append(tools, tool{name: item.name, execPath: executable, args: args})
			}
		}
	}
	for _, item := range tools {
		pathToTool := item.execPath
		if pathToTool == "" {
			var err error
			pathToTool, err = lookPath(item.name)
			if err != nil {
				continue
			}
		}
		data, runErr := a.Runner.Run(ctx, pathToTool, item.args...)
		outputLimited := len(data) > maxEvidenceOutput
		if len(data) > maxEvidenceOutput {
			data = data[:maxEvidenceOutput]
		}
		if len(data) > 0 {
			result.Evidence = append(result.Evidence, report.Evidence{Source: item.name, Output: strings.ToValidUTF8(string(data), "�")})
		}
		if runErr != nil {
			if outputLimited || strings.Contains(runErr.Error(), "output limit reached") {
				result.Warnings = append(result.Warnings, fmt.Sprintf("%s output exceeded the %d-byte safety limit; the report preserves the first %d bytes only.", item.name, maxEvidenceOutput, len(data)))
			} else {
				result.Warnings = append(result.Warnings, fmt.Sprintf("%s did not complete: %s", item.name, runErr))
			}
		} else if outputLimited {
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s output exceeded the %d-byte safety limit; the report preserves the first %d bytes only.", item.name, maxEvidenceOutput, len(data)))
		}
	}
}

func (a Analyzer) findTool(name string, lookPath func(string) (string, error)) (string, error) {
	if a.Root == "" {
		return lookPath(name)
	}
	statePath := filepath.Join(a.Root, "state.json")
	info, err := os.Lstat(statePath)
	if os.IsNotExist(err) {
		return lookPath(name)
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("RevKit state is not a regular file")
	}
	current, err := state.Load(statePath)
	if err != nil {
		return "", err
	}
	if current.Root != "" && filepath.Clean(current.Root) != filepath.Clean(a.Root) {
		return "", errors.New("RevKit state belongs to a different installation root")
	}
	tool, managed := current.Tools[name]
	if !managed || tool.Path == "" {
		return lookPath(name)
	}
	if filepath.IsAbs(tool.Path) {
		return "", errors.New("managed analyzer path must be relative to the installation root")
	}
	base := filepath.Join(a.Root, "tools", "cli", name)
	path := filepath.Join(a.Root, tool.Path)
	if !pathWithin(base, path) {
		return "", errors.New("managed analyzer path is outside its RevKit tool directory")
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm()&0111 == 0 {
		return "", errors.New("managed analyzer launcher is not an executable file")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if !pathWithin(base, resolved) {
		return "", errors.New("managed analyzer launcher resolves outside its RevKit tool directory")
	}
	return path, nil
}

func pathWithin(base, path string) bool {
	relative, err := filepath.Rel(base, path)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

var versionPattern = regexp.MustCompile(`(^|[^0-9A-Za-z.+-])v?([0-9]+)\.([0-9]+)\.([0-9]+)($|[^0-9A-Za-z.+-])`)

func verifiedAnalyzer(ctx context.Context, runner Runner, lookPath func(string) (string, error), name, minimum string) (string, string) {
	executable, err := lookPath(name)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return "", ""
		}
		return "", fmt.Sprintf("%s managed installation could not be used; skipped during analysis: %v", name, err)
	}
	output, err := runner.Run(ctx, executable, "--version")
	if err != nil {
		return "", fmt.Sprintf("%s version could not be verified; skipped during analysis.", name)
	}
	version, ok := parseStableVersion(string(output))
	if !ok {
		return "", fmt.Sprintf("%s version could not be verified; skipped during analysis.", name)
	}
	if compareVersion(version, minimum) < 0 {
		return "", fmt.Sprintf("%s %s is older than the safe minimum %s; skipped during analysis.", name, version, minimum)
	}
	return executable, ""
}

func parseStableVersion(output string) (string, bool) {
	match := versionPattern.FindStringSubmatch(output)
	if len(match) != 6 {
		return "", false
	}
	return strings.Join(match[2:5], "."), true
}

func compareVersion(left, right string) int {
	leftParts, rightParts := strings.Split(left, "."), strings.Split(right, ".")
	for index := range leftParts {
		leftNumber, leftErr := strconv.ParseUint(leftParts[index], 10, 64)
		rightNumber, rightErr := strconv.ParseUint(rightParts[index], 10, 64)
		if leftErr != nil || rightErr != nil {
			return -1
		}
		if leftNumber < rightNumber {
			return -1
		}
		if leftNumber > rightNumber {
			return 1
		}
	}
	return 0
}

func workspaceSafeEnvironment() []string {
	const capaWorkspace = "CAPA_LOAD_VIV_WORKSPACE="
	const flossWorkspace = "FLOSS_LOAD_VIV_WORKSPACE="
	environment := make([]string, 0, len(os.Environ())+2)
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, capaWorkspace) || strings.HasPrefix(value, flossWorkspace) {
			continue
		}
		environment = append(environment, value)
	}
	return append(environment, capaWorkspace+"0", flossWorkspace+"0")
}

func collectStrings(file *os.File, size int64) []string {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil
	}
	reader := bufio.NewReader(io.LimitReader(file, size))
	var output []string
	var current strings.Builder
	flush := func() {
		value := current.String()
		current.Reset()
		if len(value) < 4 {
			return
		}
		output = append(output, value)
	}
	for {
		value, err := reader.ReadByte()
		if value >= 0x20 && value <= 0x7e {
			current.WriteByte(value)
		} else {
			flush()
		}
		if err != nil {
			if err != io.EOF {
				return output
			}
			break
		}
	}
	flush()
	return output
}

func addStringEvidence(values []string, result *report.Report) {
	if len(values) == 0 {
		return
	}
	result.Evidence = append(result.Evidence, report.Evidence{Source: "Printable strings", Output: strings.Join(values, "\n")})
	interesting := importantStrings(values)
	if len(interesting) == 0 {
		return
	}
	meaning := "These look like program messages or input hints. Search for one in a disassembler to see which code uses it."
	for _, value := range interesting {
		if strings.Contains(strings.ToLower(value), "usage") {
			meaning = "A usage line often shows expected input. Look for argc (argument count) and argv (argument values), which tell a program what was entered."
			break
		}
	}
	result.Findings = append(result.Findings, report.Finding{Title: "Program messages and usage", Meaning: meaning, Why: "Strings are navigation clues, not proof of behavior. References show where code uses a string.", Evidence: interesting})
	if len(result.NextSteps) == 0 {
		return
	}
	step := result.NextSteps[0]
	if step.Tool != "Ghidra" {
		return
	}
	clue := primaryStringClue(interesting)
	step.Action = fmt.Sprintf("Search for %q in Ghidra, then inspect its XREF (code that uses this text).", clue)
	hasUsage := false
	for _, value := range interesting {
		hasUsage = hasUsage || strings.Contains(strings.ToLower(value), "usage")
	}
	if hasUsage {
		step.Action += " The usage text may describe an input argument; trace argc (argument count) and argv (argument values)."
	} else {
		step.Action += " Check the nearby branch to see what happens after this message."
	}
	result.NextSteps[0] = step
}

func importantStrings(values []string) []string {
	strong := summaryMatches(values, strongSummaryCluePattern)
	if len(strong) > 0 {
		if len(strong) > 5 {
			return strong[:5]
		}
		return strong
	}
	general := summaryMatches(values, generalSummaryCluePattern)
	if len(general) > 5 {
		return general[:5]
	}
	return general
}

func summaryMatches(values []string, pattern *regexp.Regexp) []string {
	var matches []string
	for _, value := range values {
		if len(value) > maxSummaryScan {
			continue
		}
		for _, clue := range pattern.FindAllString(separateCaseBoundaries(value), -1) {
			clue = strings.TrimSpace(clue)
			duplicate := false
			for _, existing := range matches {
				if existing == clue {
					duplicate = true
					break
				}
			}
			if !duplicate {
				matches = append(matches, clue)
			}
		}
	}
	return matches
}

func separateCaseBoundaries(value string) string {
	var output strings.Builder
	output.Grow(len(value))
	data := []byte(value)
	for index, current := range data {
		lowerToUpper := index > 0 && data[index-1] >= 'a' && data[index-1] <= 'z' && current >= 'A' && current <= 'Z'
		acronymEnd := index > 0 && index+1 < len(data) && data[index-1] >= 'A' && data[index-1] <= 'Z' && current >= 'A' && current <= 'Z' && data[index+1] >= 'a' && data[index+1] <= 'z'
		if lowerToUpper || acronymEnd {
			output.WriteByte(' ')
		}
		output.WriteByte(current)
	}
	return output.String()
}

var strongSummaryCluePattern = regexp.MustCompile(`(?i)\b(?:wrong|incorrect|invalid)\s+(?:password|passcode|passphrase|pass)\b|\bgratz(?:\s+man\s*:\))?|\bcongrat(?:ulations)?\b|\busage:\s*%s\s+pass\b|\busage\s*:`)
var generalSummaryCluePattern = regexp.MustCompile(`(?i)\b(?:success(?:ful)?|failure|failed)\b`)

func primaryStringClue(values []string) string {
	for _, value := range values {
		lower := strings.ToLower(value)
		if strings.Contains(lower, "wrong") || strings.Contains(lower, "incorrect") || strings.Contains(lower, "invalid") || strings.Contains(lower, "failure") || strings.Contains(lower, "failed") || strings.Contains(lower, "error") {
			return value
		}
	}
	return values[0]
}

func elfNextSteps() []report.NextStep {
	return []report.NextStep{{Action: "Open the ELF in Ghidra and inspect its entry point and references to useful strings.", Tool: "Ghidra", Learn: []string{"ELF headers (file metadata), sections (named regions), and segments (loader regions)", "x86 calling conventions", "Ghidra strings and XREFs (references to code that uses text)"}, Searches: []string{"ELF inspect sections readelf", "Ghidra string xref beginner", "Ghidra decompiler beginner"}}}
}

func peNextSteps() []report.NextStep {
	return []report.NextStep{{Action: "Open the PE in Ghidra and find references to useful strings or imported functions.", Tool: "Ghidra", Learn: []string{"PE32 and PE32+ (32-bit and 64-bit Windows executable formats)", "Windows imports (functions supplied by libraries)", "C command-line arguments (argc/argv: argument count and values)", "Ghidra strings and XREFs (references to code that uses text)"}, Searches: []string{"PE32 executable beginner", "Ghidra string xref beginner", "Ghidra decompiler beginner"}}}
}

func headerNextSteps() []report.NextStep {
	return []report.NextStep{{Action: "Use xxd to inspect the first bytes and compare the header with known file signatures.", Tool: "xxd", Learn: []string{"magic bytes", "hexadecimal byte offsets"}, Searches: []string{"file format magic bytes Linux", "xxd hex viewer beginner"}}}
}

func isZIPHeader(data []byte) bool {
	return len(data) >= 4 && data[0] == 'P' && data[1] == 'K' && (binary.LittleEndian.Uint16(data[2:4]) == 0x0403 || binary.LittleEndian.Uint16(data[2:4]) == 0x0605 || binary.LittleEndian.Uint16(data[2:4]) == 0x0807)
}

func isText(data []byte) bool {
	if len(data) == 0 || !utf8.Valid(data) {
		return false
	}
	for _, value := range string(data) {
		if unicode.IsControl(value) && value != '\t' && value != '\n' && value != '\r' {
			return false
		}
	}
	return true
}

func yesNo(value bool) string {
	if value {
		return "present"
	}
	return "absent"
}
