package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

// evalPath fully resolves p, failing the test if it cannot be resolved. It is
// used to compare paths that may traverse symlinked temporary directories.
func evalPath(t *testing.T, p string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", p, err)
	}
	return resolved
}

func mustStat(t *testing.T, p string) os.FileInfo {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("Stat(%q): %v", p, err)
	}
	return fi
}

// TestOpenMountTarget verifies that the mount target used by openContainerFS is
// resolved in a symlink-safe way and is pinned by a file descriptor, so it
// cannot be redirected outside of the container root — neither by symlinks
// present at resolution time nor by a symlink swapped in afterwards
// (CVE-2026-42306).
func TestOpenMountTarget(t *testing.T) {
	t.Run("resolves within root", func(t *testing.T) {
		root := t.TempDir()
		dest := filepath.Join(root, "mnt")
		if err := os.Mkdir(dest, 0o755); err != nil {
			t.Fatal(err)
		}

		targetFile, targetPath, err := openMountTarget(root, "mnt")
		if err != nil {
			t.Fatalf("openMountTarget: %v", err)
		}
		defer targetFile.Close()

		resolved, err := os.Readlink(targetPath)
		if err != nil {
			t.Fatalf("Readlink(%q): %v", targetPath, err)
		}
		if want := evalPath(t, dest); resolved != want {
			t.Errorf("mount target resolved to %q, want %q", resolved, want)
		}
	})

	t.Run("absolute symlink cannot escape root", func(t *testing.T) {
		root := t.TempDir()
		// An absolute symlink must be interpreted relative to the container
		// root, not to the host root.
		inRoot := filepath.Join(root, "etc")
		if err := os.Mkdir(inRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/etc", filepath.Join(root, "escape")); err != nil {
			t.Fatal(err)
		}

		targetFile, targetPath, err := openMountTarget(root, "escape")
		if err != nil {
			t.Fatalf("openMountTarget: %v", err)
		}
		defer targetFile.Close()

		resolved, err := os.Readlink(targetPath)
		if err != nil {
			t.Fatalf("Readlink(%q): %v", targetPath, err)
		}
		if want := evalPath(t, inRoot); resolved != want {
			t.Errorf("mount target resolved to %q, want %q (escaped the root)", resolved, want)
		}
	})

	t.Run("parent traversal is clamped to root", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "deep", "sub"), 0o755); err != nil {
			t.Fatal(err)
		}

		targetFile, targetPath, err := openMountTarget(root, filepath.Join("deep", "sub", "..", "..", "..", ".."))
		if err != nil {
			t.Fatalf("openMountTarget: %v", err)
		}
		defer targetFile.Close()

		resolved, err := os.Readlink(targetPath)
		if err != nil {
			t.Fatalf("Readlink(%q): %v", targetPath, err)
		}
		if want := evalPath(t, root); resolved != want {
			t.Errorf("mount target resolved to %q, want %q (traversed above the root)", resolved, want)
		}
	})

	// This is the CVE-2026-42306 race itself: the mount target used to be
	// resolved by name and then handed to mount(2) by name, so an attacker
	// controlling the container filesystem could replace the resolved
	// directory with a symlink to a host path in between and have the daemon
	// bind-mount over that host path instead.
	t.Run("symlink swapped in after resolution cannot redirect the target", func(t *testing.T) {
		base := evalPath(t, t.TempDir())
		root := filepath.Join(base, "root")
		hostSecret := filepath.Join(base, "host-secret")
		if err := os.MkdirAll(hostSecret, 0o755); err != nil {
			t.Fatal(err)
		}
		dest := filepath.Join(root, "mnt")
		if err := os.MkdirAll(dest, 0o755); err != nil {
			t.Fatal(err)
		}

		// Resolve the mount target, as openContainerFS does before mounting.
		targetFile, targetPath, err := openMountTarget(root, "mnt")
		if err != nil {
			t.Fatalf("openMountTarget: %v", err)
		}
		defer targetFile.Close()

		// Win the race: move the real directory aside and drop a symlink to a
		// host path in its place.
		moved := filepath.Join(root, "mnt-moved")
		if err := os.Rename(dest, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(hostSecret, dest); err != nil {
			t.Fatal(err)
		}

		// Sanity check that the swap is effective for by-name resolution, which
		// is what the pre-fix code did: it would now mount onto the host path.
		byName := evalPath(t, dest)
		if byName != hostSecret {
			t.Fatalf("test setup: by-name resolution of %q gave %q, want %q", dest, byName, hostSecret)
		}

		// The fd-pinned target is unaffected by the swap: it still refers to
		// the inode that was resolved inside the root.
		resolved, err := os.Readlink(targetPath)
		if err != nil {
			t.Fatalf("Readlink(%q): %v", targetPath, err)
		}
		if resolved == hostSecret {
			t.Fatalf("mount target followed the swapped-in symlink to the host path %q", hostSecret)
		}
		if want := evalPath(t, moved); resolved != want {
			t.Errorf("mount target resolved to %q, want %q", resolved, want)
		}
		if !os.SameFile(mustStat(t, resolved), mustStat(t, moved)) {
			t.Errorf("mount target %q is not the same file as the originally resolved directory %q", resolved, moved)
		}
	})
}
