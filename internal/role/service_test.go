package role

import (
	"context"
	"errors"
	"testing"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
)

func TestCreateRejectsDuplicateCode(t *testing.T) {
	service := NewService(&fakeStore{roleCodeExists: true})

	_, err := service.Create(t.Context(), Actor{UserID: "user-001", IsAdmin: true}, CreateInput{
		Code: "ops",
		Name: "Ops",
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("Create() error = %v", err)
	}
}

func TestListRestrictsNormalUserToOwnAndSystemRoles(t *testing.T) {
	ownerID := "user-001"
	otherID := "user-002"
	store := &fakeStore{roles: []model.Role{
		{BaseModel: model.BaseModel{ID: "role-system"}, Code: "system", System: true},
		{BaseModel: model.BaseModel{ID: "role-own"}, Code: "own", OwnerUserID: &ownerID},
		{BaseModel: model.BaseModel{ID: "role-other"}, Code: "other", OwnerUserID: &otherID},
	}}
	service := NewService(store)

	items, err := service.List(t.Context(), Actor{UserID: ownerID})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("items = %#v", items)
	}
}

func TestUpdateRejectsSystemRole(t *testing.T) {
	service := NewService(&fakeStore{role: &model.Role{
		BaseModel: model.BaseModel{ID: "role-admin"},
		Code:      model.RoleAdminCode,
		System:    true,
	}})

	_, err := service.Update(t.Context(), Actor{UserID: "admin", IsAdmin: true}, UpdateInput{
		ID:   "role-admin",
		Name: "Admin",
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("Update() error = %v", err)
	}
}

func TestDeleteRejectsAdminRole(t *testing.T) {
	service := NewService(&fakeStore{role: &model.Role{
		BaseModel: model.BaseModel{ID: "role-admin"},
		Code:      model.RoleAdminCode,
		System:    true,
	}})

	err := service.Delete(t.Context(), Actor{UserID: "admin", IsAdmin: true}, "role-admin")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestNormalUserCannotAssignPermissionTheyDoNotHave(t *testing.T) {
	service := NewService(&fakeStore{permissions: []model.Permission{{
		BaseModel: model.BaseModel{ID: "perm-user"},
		Code:      "user:manage",
	}}})

	_, err := service.Create(t.Context(), Actor{UserID: "user-001", Permissions: []string{"app:manage"}}, CreateInput{
		Code:          "ops",
		Name:          "Ops",
		PermissionIDs: []string{"perm-user"},
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("Create() error = %v", err)
	}
}

type fakeStore struct {
	roleCodeExists bool
	role           *model.Role
	roles          []model.Role
	permissions    []model.Permission
}

func (s *fakeStore) RoleCodeExists(_ context.Context, _ string) (bool, error) {
	return s.roleCodeExists, nil
}

func (s *fakeStore) Create(_ context.Context, role *model.Role, _ []string) error {
	s.role = role
	return nil
}

func (s *fakeStore) List(_ context.Context, filter ListFilter) ([]model.Role, error) {
	items := []model.Role{}
	for _, item := range s.roles {
		if filter.OwnerUserID != "" {
			if item.System || (item.OwnerUserID != nil && *item.OwnerUserID == filter.OwnerUserID) {
				items = append(items, item)
			}
			continue
		}
		items = append(items, item)
	}
	return items, nil
}

func (s *fakeStore) FindByID(_ context.Context, id string) (*model.Role, error) {
	if s.role == nil || s.role.ID != id {
		return nil, ErrNotFound
	}
	return s.role, nil
}

func (s *fakeStore) Update(_ context.Context, role *model.Role, _ []string) error {
	s.role = role
	return nil
}

func (s *fakeStore) Delete(_ context.Context, _ string) error {
	return nil
}

func (s *fakeStore) ListPermissions(_ context.Context) ([]model.Permission, error) {
	return s.permissions, nil
}

func (s *fakeStore) FindPermissionsByIDs(_ context.Context, _ []string) ([]model.Permission, error) {
	return s.permissions, nil
}
