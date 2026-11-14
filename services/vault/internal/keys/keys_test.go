package keys

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func privateDir(t *testing.T) string {
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestPepperCreatedOnceAndStable(t *testing.T) {
	d := privateDir(t)
	k1, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1.LoginID("alice"), k2.LoginID("alice")) {
		t.Fatal("pepper changed between loads")
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(d, pepperFile))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o400 {
			t.Fatalf("pepper mode %o", fi.Mode().Perm())
		}
	}
}

func TestRejectsBadPepper(t *testing.T) {
	d := privateDir(t)
	if err := os.WriteFile(filepath.Join(d, pepperFile), []byte("short"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(d); err == nil {
		t.Fatal("accepted short pepper")
	}
}

func TestRejectsOpenDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions only")
	}
	d := t.TempDir()
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(d); err == nil {
		t.Fatal("accepted world-readable data dir")
	}
}

func TestBranchesIndependent(t *testing.T) {
	k := ForTest()
	x := make([]byte, 32)
	if bytes.Equal(k.AuthHash(x), k.RecoveryHash(x)) {
		t.Fatal("auth and recovery hashes collide")
	}
	if bytes.Equal(k.LoginID("a"), k.InviteID([]byte("a"))) {
		t.Fatal("login and invite ids collide")
	}
}
