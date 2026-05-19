package ui

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNewHandlerNormalizesPrefix(t *testing.T) {
	handler, err := NewHandler("/ui")
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	if handler.prefix != "/ui/" {
		t.Fatalf("prefix = %q", handler.prefix)
	}
}

func TestLoginShowsWorkspaceWhenInitialDataLoadFails(t *testing.T) {
	if _, err := os.ReadFile(filepath.Join("static", "index.html")); err != nil {
		t.Fatalf("read index: %v", err)
	}
	app, err := os.ReadFile(filepath.Join("static", "app.js"))
	if err != nil {
		t.Fatalf("read app: %v", err)
	}
	script := fmt.Sprintf(`
class ClassList {
  constructor() { this.values = new Set(); }
  add(v) { this.values.add(v); }
  remove(v) { this.values.delete(v); }
  toggle(v, force) { if (force === undefined ? !this.values.has(v) : force) this.add(v); else this.remove(v); }
  contains(v) { return this.values.has(v); }
}
class Element {
  constructor(tag, id = "") { this.tagName = tag; this.id = id; this.children = []; this.dataset = {}; this.classList = new ClassList(); this.listeners = {}; this.style = {}; this.value = ""; this.textContent = ""; this.innerHTML = ""; this.required = false; this.name = ""; this.type = ""; this.options = []; }
  appendChild(child) { this.children.push(child); return child; }
  addEventListener(type, fn) { this.listeners[type] = fn; }
  matches(selector) { return selector === "button[data-view]" && this.tagName === "button" && this.dataset.view; }
  querySelectorAll() { return []; }
  showModal() {}
  close() {}
}
const ids = {};
function ensure(id) { return ids[id] || (ids[id] = new Element("div", id)); }
global.document = {
  querySelector(selector) { if (selector.startsWith("#")) return ensure(selector.slice(1)); return new Element("div"); },
  querySelectorAll() { return []; },
  createElement(tag) { return new Element(tag); }
};
global.localStorage = { values: {}, getItem(k) { return this.values[k] || ""; }, setItem(k, v) { this.values[k] = String(v); }, removeItem(k) { delete this.values[k]; } };
global.FormData = class { constructor() {} forEach() {} };
global.URLSearchParams = class { constructor() { this.values = []; } set(k, v) { this.values.push([k, v]); } toString() { return ""; } };
global.confirm = () => true;
let calls = [];
global.fetch = async (path) => {
  calls.push(path);
  if (path === "/api/auth/login") return { ok: true, status: 200, headers: { get() { return ""; } }, text: async () => JSON.stringify({ code: 0, data: { accessToken: "access", refreshToken: "refresh" } }) };
  return { ok: false, status: 403, headers: { get() { return ""; } }, text: async () => JSON.stringify({ message: "forbidden" }) };
};
%s
ensure("username").value = "admin";
ensure("password").value = "secret";
Promise.resolve(ensure("loginForm").listeners.submit({ preventDefault() {} })).then(() => setTimeout(() => {
  if (!ensure("loginPanel").classList.contains("hidden")) throw new Error("login panel still visible");
  if (ensure("workspace").classList.contains("hidden")) throw new Error("workspace hidden");
  if (ensure("alert").classList.contains("hidden")) throw new Error("error alert not shown");
}, 0));
`, string(app))
	scriptPath := filepath.Join(t.TempDir(), "ui-login-test.js")
	if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
		t.Fatalf("write node script: %v", err)
	}
	cmd := exec.Command("node", scriptPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("node ui behavior failed: %v\n%s", err, output)
	}
}

func TestHandlerServesManagementUIAssets(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, err := NewHandler("/ui/")
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	router := gin.New()
	handler.RegisterRoutes(router)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "modal") || !strings.Contains(rec.Body.String(), "鉴权限流管理后台") {
		t.Fatalf("ui body missing management shell")
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/ui/app.js", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("app.js status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "limitRules") || !strings.Contains(rec.Body.String(), "refreshSession") {
		t.Fatalf("app.js missing management behavior")
	}
}
