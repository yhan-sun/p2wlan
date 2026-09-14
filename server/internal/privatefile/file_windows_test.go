package privatefile

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestPrivateFileDoesNotInheritPermissiveParent(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private-test")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(directory, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	insecure := filepath.Join(directory, "inherited.env")
	if err := os.WriteFile(insecure, []byte("public fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(insecure); err == nil {
		t.Fatal("chmod 0600 must not be mistaken for a private Windows ACL")
	}
	secure := filepath.Join(directory, "部署-secret.env")
	if err := WriteNew(secure, []byte("secret fixture")); err != nil {
		t.Fatal(err)
	}
	if err := Verify(secure); err != nil {
		t.Fatal(err)
	}
}
