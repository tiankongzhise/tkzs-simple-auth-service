package ui

import "testing"

func TestNewHandlerNormalizesPrefix(t *testing.T) {
	handler, err := NewHandler("/ui")
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	if handler.prefix != "/ui/" {
		t.Fatalf("prefix = %q", handler.prefix)
	}
}
