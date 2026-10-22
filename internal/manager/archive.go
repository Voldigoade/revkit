package manager

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const maxExtractedSize int64 = 8 << 30

func archivePath(name string) (string, error) {
	if name == "" || strings.IndexByte(name, 0) >= 0 || strings.Contains(name, "\\") {
		return "", fmt.Errorf("invalid archive path %q", name)
	}
	for strings.HasPrefix(name, "./") {
		name = strings.TrimPrefix(name, "./")
	}
	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("absolute archive path %q", name)
	}
	if len(name) >= 2 && name[1] == ':' {
		return "", fmt.Errorf("absolute archive path %q", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", fmt.Errorf("archive path escapes destination: %q", name)
		}
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." {
		return ".", nil
	}
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("archive path escapes destination: %q", name)
	}
	return clean, nil
}

func extractZip(archive, destination string) error {
	r, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer r.Close()
	var total uint64
	for _, entry := range r.File {
		name, err := archivePath(entry.Name)
		if err != nil {
			return err
		}
		if name == "." {
			continue
		}
		if entry.UncompressedSize64 > uint64(maxExtractedSize)-total {
			return fmt.Errorf("archive expands beyond the 8 GiB limit")
		}
		total += entry.UncompressedSize64
		mode := entry.Mode()
		if mode&os.ModeSymlink != 0 || mode&os.ModeType != 0 && !mode.IsDir() {
			return fmt.Errorf("archive contains unsupported special entry %q", entry.Name)
		}
		dest := filepath.Join(destination, name)
		if mode.IsDir() || strings.HasSuffix(entry.Name, "/") {
			if err := safeMkdirAll(destination, name); err != nil {
				return err
			}
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			return err
		}
		perm := mode.Perm() & 0755
		if perm == 0 {
			perm = 0644
		}
		if err := writeExtracted(destination, name, rc, int64(entry.UncompressedSize64), perm); err != nil {
			rc.Close()
			return err
		}
		if err := rc.Close(); err != nil {
			return err
		}
		_ = dest
	}
	return nil
}

func extractTarXZ(ctx context.Context, archive, destination string) error {
	cmd := exec.CommandContext(ctx, "xz", "-dc", archive)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr cappedBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start xz: %w", err)
	}
	extractErr := extractTar(stdout, destination)
	if extractErr != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if extractErr != nil {
		return extractErr
	}
	if waitErr != nil {
		return fmt.Errorf("decompress Pwndbg archive: %w: %s", waitErr, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func extractTar(source io.Reader, destination string) error {
	tr := tar.NewReader(source)
	var total int64
	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name, err := archivePath(header.Name)
		if err != nil {
			return err
		}
		if name == "." {
			continue
		}
		if header.Size < 0 || header.Size > maxExtractedSize-total {
			return fmt.Errorf("archive expands beyond the 8 GiB limit")
		}
		total += header.Size
		switch header.Typeflag {
		case tar.TypeDir:
			if err := safeMkdirAll(destination, name); err != nil {
				return err
			}
		case tar.TypeReg:
			perm := os.FileMode(header.Mode).Perm() & 0755
			if perm == 0 {
				perm = 0644
			}
			if err := writeExtracted(destination, name, tr, header.Size, perm); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := extractSymlink(destination, name, header.Linkname); err != nil {
				return err
			}
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			continue
		default:
			return fmt.Errorf("archive contains unsupported entry type %d at %q", header.Typeflag, header.Name)
		}
	}
}

func safeMkdirAll(root, rel string) error {
	if _, err := archivePath(filepath.ToSlash(rel)); err != nil {
		return err
	}
	dest := filepath.Join(root, rel)
	if info, err := os.Lstat(dest); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
		return fmt.Errorf("archive directory collides with a non-directory entry")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := ensureSafeParents(root, rel); err != nil {
		return err
	}
	return os.MkdirAll(dest, 0755)
}

func ensureSafeParents(root, rel string) error {
	parent := filepath.Dir(rel)
	if parent == "." {
		return nil
	}
	current := root
	for _, part := range strings.Split(parent, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("archive path traverses a non-directory entry")
		}
	}
	return nil
}

func writeExtracted(root, rel string, source io.Reader, size int64, mode os.FileMode) error {
	if err := ensureSafeParents(root, rel); err != nil {
		return err
	}
	dest := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.CopyN(f, source, size)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(dest)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(dest)
		return closeErr
	}
	return nil
}

func extractSymlink(root, rel, target string) error {
	if target == "" || strings.Contains(target, "\\") || strings.IndexByte(target, 0) >= 0 || filepath.IsAbs(target) {
		return fmt.Errorf("archive contains unsafe symlink %q", rel)
	}
	resolved, err := archivePath(filepath.ToSlash(filepath.Join(filepath.Dir(rel), target)))
	if err != nil {
		return fmt.Errorf("archive contains escaping symlink %q", rel)
	}
	if resolved == "." {
		return fmt.Errorf("archive contains invalid symlink %q", rel)
	}
	if err := ensureSafeParents(root, rel); err != nil {
		return err
	}
	dest := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	return os.Symlink(target, dest)
}

func copyFile(source, destination string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(destination)
		return copyErr
	}
	return closeErr
}

func findNamed(root, name string) string {
	var found string
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || found != "" || entry.IsDir() || entry.Name() != name {
			return nil
		}
		info, err := entry.Info()
		if err == nil && info.Mode().IsRegular() {
			found = path
		}
		return nil
	})
	return found
}

func binaryArch(file string) (string, bool, error) {
	f, err := elf.Open(file)
	if err != nil {
		if isELF, _ := hasELFHeader(file); isELF {
			return "", false, fmt.Errorf("invalid ELF launcher: %w", err)
		}
		return "", false, nil
	}
	defer f.Close()
	if f.Machine == elf.EM_X86_64 {
		return "x86_64", true, nil
	}
	return strings.ToLower(f.Machine.String()), true, nil
}

func hasELFHeader(file string) (bool, error) {
	f, err := os.Open(file)
	if err != nil {
		return false, err
	}
	defer f.Close()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false, err
	}
	return bytes.Equal(magic[:], []byte{0x7f, 'E', 'L', 'F'}), nil
}

type cappedBuffer struct{ bytes.Buffer }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	remaining := 64<<10 - b.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.Buffer.Write(p)
	}
	return original, nil
}
