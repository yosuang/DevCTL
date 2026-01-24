package pkgmgr

import (
	"context"
)

type mockManager struct{}

func (m *mockManager) Install(_ context.Context, _ ...string) error   { return nil }
func (m *mockManager) Uninstall(_ context.Context, _ ...string) error { return nil }
func (m *mockManager) List(_ context.Context) ([]Package, error)      { return nil, nil }
