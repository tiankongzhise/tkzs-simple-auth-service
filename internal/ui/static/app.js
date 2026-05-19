const endpoints = {
  users: { title: "用户", path: "/api/users" },
  apps: { title: "APP", path: "/api/apps" },
  roles: { title: "角色", path: "/api/roles" },
  oidc: { title: "OIDC Client", path: "/api/oidc-clients" },
  services: { title: "服务", path: "/api/services" },
  logs: { title: "日志", path: "/api/logs?type=operation" },
  statistics: { title: "限流统计", path: "/api/limit-statistics" },
  health: { title: "健康检测", path: "/api/health-checks" }
};

const loginPanel = document.querySelector("#loginPanel");
const workspace = document.querySelector("#workspace");
const output = document.querySelector("#output");
const title = document.querySelector("#viewTitle");
const tokenKey = "authlimit.accessToken";
let currentView = "users";

function token() {
  return localStorage.getItem(tokenKey) || "";
}

function setSession(accessToken) {
  localStorage.setItem(tokenKey, accessToken);
  loginPanel.classList.add("hidden");
  workspace.classList.remove("hidden");
}

function clearSession() {
  localStorage.removeItem(tokenKey);
  loginPanel.classList.remove("hidden");
  workspace.classList.add("hidden");
  output.textContent = "";
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (token()) headers.Authorization = `Bearer ${token()}`;
  const response = await fetch(path, { ...options, headers });
  const renewed = response.headers.get("X-Access-Token");
  if (renewed) localStorage.setItem(tokenKey, renewed);
  const text = await response.text();
  const body = text ? JSON.parse(text) : {};
  if (!response.ok) throw new Error(body.message || response.statusText);
  return body;
}

async function loadView(view) {
  currentView = view;
  const meta = endpoints[view];
  title.textContent = meta.title;
  output.textContent = "加载中...";
  document.querySelectorAll("#tabs button").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === view);
  });
  try {
    const body = await api(meta.path);
    output.textContent = JSON.stringify(body.data ?? body, null, 2);
  } catch (error) {
    output.textContent = error.message;
  }
}

document.querySelector("#loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  output.textContent = "";
  try {
    const body = await api("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: document.querySelector("#username").value,
        password: document.querySelector("#password").value
      })
    });
    setSession(body.data.accessToken);
    await loadView(currentView);
  } catch (error) {
    output.textContent = error.message;
  }
});

document.querySelector("#tabs").addEventListener("click", (event) => {
  if (event.target.matches("button[data-view]")) {
    loadView(event.target.dataset.view);
  }
});

document.querySelector("#refreshBtn").addEventListener("click", () => loadView(currentView));
document.querySelector("#logoutBtn").addEventListener("click", clearSession);

if (token()) {
  setSession(token());
  loadView(currentView);
}
