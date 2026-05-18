package bootstrap

import "testing"

func TestSystemPermissionsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, permission := range SystemPermissions() {
		if permission.Code == "" || permission.Name == "" || permission.Module == "" || permission.Action == "" {
			t.Fatalf("invalid permission seed: %#v", permission)
		}
		if seen[permission.Code] {
			t.Fatalf("duplicate permission code %q", permission.Code)
		}
		seen[permission.Code] = true
	}
}

func TestAdminRoleSeed(t *testing.T) {
	role := AdminRole()
	if role.Code != "admin" || !role.System {
		t.Fatalf("admin role = %#v", role)
	}
}
