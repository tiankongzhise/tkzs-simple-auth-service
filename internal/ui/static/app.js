const tokenKey = "authlimit.accessToken";
const refreshKey = "authlimit.refreshToken";

const state = {
  currentView: "users",
  data: {},
  roles: [],
  permissions: [],
  services: []
};

const el = {
  loginPanel: document.querySelector("#loginPanel"),
  workspace: document.querySelector("#workspace"),
  loginForm: document.querySelector("#loginForm"),
  loginMessage: document.querySelector("#loginMessage"),
  logoutBtn: document.querySelector("#logoutBtn"),
  sessionState: document.querySelector("#sessionState"),
  tabs: document.querySelector("#tabs"),
  title: document.querySelector("#viewTitle"),
  meta: document.querySelector("#viewMeta"),
  createBtn: document.querySelector("#createBtn"),
  refreshBtn: document.querySelector("#refreshBtn"),
  filterForm: document.querySelector("#filterForm"),
  alert: document.querySelector("#alert"),
  tableHead: document.querySelector("#tableHead"),
  tableBody: document.querySelector("#tableBody"),
  modal: document.querySelector("#modal"),
  modalForm: document.querySelector("#modalForm"),
  modalTitle: document.querySelector("#modalTitle"),
  modalBody: document.querySelector("#modalBody"),
  modalSubmit: document.querySelector("#modalSubmit"),
  modalCancel: document.querySelector("#modalCancel"),
  modalClose: document.querySelector("#modalClose")
};

const fieldTypes = {
  text: "text",
  password: "password",
  number: "number",
  url: "url",
  datetime: "datetime-local",
  checkbox: "checkbox",
  textarea: "textarea",
  select: "select",
  multiselect: "multiselect"
};

const views = {
  users: {
    title: "用户管理",
    meta: "注册、资料、状态、密码与角色分配",
    path: "/api/users",
    preload: preloadRoles,
    columns: [
      ["username", "用户名"],
      ["displayName", "显示名"],
      ["status", "状态", badge],
      ["roles", "角色", listText],
      ["createdAt", "创建时间", shortTime]
    ],
    filters: [],
    create: {
      title: "注册用户",
      fields: [
        textField("username", "用户名"),
        passwordField("password", "密码"),
        textField("displayName", "显示名", false)
      ],
      submit: (payload) => api("/api/users/register", { method: "POST", body: payload })
    },
    edit: {
      title: "编辑用户",
      fields: [textField("displayName", "显示名", false)],
      submit: (item, payload) => api(`/api/users/${item.id}`, { method: "PUT", body: payload })
    },
    actions: [
      action("编辑", "ghost", (item) => openEdit(item)),
      action("启用", "ghost", (item) => updateUserStatus(item, "enabled"), (item) => item.status !== "enabled"),
      action("禁用", "ghost", (item) => updateUserStatus(item, "disabled"), (item) => item.status === "enabled"),
      action("密码", "ghost", (item) => openPassword(item)),
      action("角色", "ghost", (item) => openRoleAssign("user", item)),
      action("删除", "danger", (item) => removeItem(`/api/users/${item.id}`))
    ]
  },
  apps: {
    title: "APP 管理",
    meta: "机器调用应用、Secret 重置与角色分配",
    path: "/api/apps",
    preload: preloadRoles,
    columns: [
      ["appId", "APPID"],
      ["name", "名称"],
      ["status", "状态", badge],
      ["ownerUserId", "归属用户", narrow],
      ["createdAt", "创建时间", shortTime]
    ],
    create: {
      title: "创建 APP",
      fields: [textField("name", "名称")],
      submit: (payload) => api("/api/apps", { method: "POST", body: payload }),
      after: showSecret("AppSecret", "appSecret")
    },
    edit: {
      title: "编辑 APP",
      fields: [textField("name", "名称"), selectField("status", "状态", statusOptions)],
      submit: (item, payload) => api(`/api/apps/${item.id}`, { method: "PUT", body: payload })
    },
    actions: [
      action("编辑", "ghost", (item) => openEdit(item)),
      action("重置密钥", "ghost", resetAppSecret),
      action("角色", "ghost", (item) => openRoleAssign("app", item)),
      action("删除", "danger", (item) => removeItem(`/api/apps/${item.id}`))
    ]
  },
  roles: {
    title: "角色权限",
    meta: "角色创建、权限分配和权限点查询",
    path: "/api/roles",
    preload: preloadRoles,
    columns: [
      ["code", "标识"],
      ["name", "名称"],
      ["system", "系统", boolText],
      ["permissions", "权限", permissionText],
      ["createdAt", "创建时间", shortTime]
    ],
    create: {
      title: "创建角色",
      fields: [
        textField("code", "角色标识"),
        textField("name", "名称"),
        textAreaField("description", "描述", false),
        multiSelectField("permissionIds", "权限", () => state.permissions.map((p) => [p.id, `${p.code} ${p.name}`]))
      ],
      submit: (payload) => api("/api/roles", { method: "POST", body: payload })
    },
    edit: {
      title: "编辑角色",
      fields: [
        textField("name", "名称"),
        textAreaField("description", "描述", false),
        multiSelectField("permissionIds", "权限", () => state.permissions.map((p) => [p.id, `${p.code} ${p.name}`]))
      ],
      submit: (item, payload) => api(`/api/roles/${item.id}`, { method: "PUT", body: payload })
    },
    actions: [
      action("编辑", "ghost", (item) => openEdit(item), (item) => !item.system),
      action("删除", "danger", (item) => removeItem(`/api/roles/${item.id}`), (item) => !item.system)
    ]
  },
  oidc: {
    title: "OIDC Client",
    meta: "OAuth2/OIDC 客户端、回调地址与 Secret",
    path: "/api/oidc-clients",
    columns: [
      ["clientId", "ClientID"],
      ["name", "名称"],
      ["redirectUri", "回调地址", narrow],
      ["status", "状态", badge],
      ["createdAt", "创建时间", shortTime]
    ],
    create: {
      title: "创建 OIDC Client",
      fields: [textField("name", "名称"), urlField("redirectUri", "回调地址")],
      submit: (payload) => api("/api/oidc-clients", { method: "POST", body: payload }),
      after: showSecret("ClientSecret", "clientSecret")
    },
    edit: {
      title: "编辑 OIDC Client",
      fields: [textField("name", "名称"), urlField("redirectUri", "回调地址"), selectField("status", "状态", statusOptions)],
      submit: (item, payload) => api(`/api/oidc-clients/${item.id}`, { method: "PUT", body: payload })
    },
    actions: [
      action("编辑", "ghost", (item) => openEdit(item)),
      action("重置密钥", "ghost", resetOIDCSecret),
      action("删除", "danger", (item) => removeItem(`/api/oidc-clients/${item.id}`))
    ]
  },
  services: {
    title: "服务管理",
    meta: "服务注册、审核、发现与健康状态",
    path: "/api/services",
    preload: preloadServices,
    filters: [
      textField("name", "服务名", false),
      selectField("health", "健康状态", [["", "全部"], ["healthy", "健康"], ["degraded", "亚健康"], ["unhealthy", "异常"], ["unknown", "未知"]], false)
    ],
    columns: [
      ["name", "名称"],
      ["code", "编码"],
      ["baseUrl", "地址", narrow],
      ["status", "状态", badge],
      ["healthStatus", "健康", badge],
      ["approved", "已审核", boolText]
    ],
    create: {
      title: "注册服务",
      fields: [
        textField("name", "名称"),
        textField("code", "编码"),
        urlField("baseUrl", "服务地址"),
        textField("healthPath", "健康路径", false, "/health"),
        numberField("healthCheckInterval", "检测间隔秒", false)
      ],
      submit: (payload) => api("/api/services", { method: "POST", body: payload })
    },
    edit: {
      title: "编辑服务",
      fields: [
        textField("name", "名称", false),
        urlField("baseUrl", "服务地址", false),
        textField("healthPath", "健康路径", false),
        numberField("healthCheckInterval", "检测间隔秒", false),
        selectField("status", "状态", [["", "不变"], ["pending", "待审核"], ["approved", "已审核"], ["offline", "下线"]], false),
        selectField("healthStatus", "健康状态", [["", "不变"], ["healthy", "健康"], ["degraded", "亚健康"], ["unhealthy", "异常"], ["unknown", "未知"]], false)
      ],
      submit: (item, payload) => api(`/api/services/${item.id}`, { method: "PUT", body: payload })
    },
    actions: [
      action("编辑", "ghost", (item) => openEdit(item)),
      action("审核", "ghost", (item) => approveService(item), (item) => !item.approved),
      action("删除", "danger", (item) => removeItem(`/api/services/${item.id}`))
    ]
  },
  limitRules: {
    title: "限流规则",
    meta: "服务级动态限流规则，未配置时继承全局默认规则",
    path: "/api/limit-rules",
    preload: preloadServices,
    filters: [
      serviceSelect("serviceId", "服务", false, true),
      selectField("dimension", "维度", [["", "全部"], ["ip", "IP"], ["user_id", "用户"], ["app_id", "APP"], ["path", "接口"]], false),
      selectField("enabled", "启用", [["", "全部"], ["true", "启用"], ["false", "禁用"]], false)
    ],
    columns: [
      ["serviceId", "服务", serviceName],
      ["dimension", "维度"],
      ["granularity", "粒度"],
      ["capacity", "容量"],
      ["ratePerSecond", "每秒令牌"],
      ["enabled", "启用", boolText]
    ],
    create: {
      title: "创建限流规则",
      fields: limitRuleFields(true),
      submit: (payload) => api("/api/limit-rules", { method: "POST", body: payload })
    },
    edit: {
      title: "编辑限流规则",
      fields: limitRuleFields(false),
      submit: (item, payload) => api(`/api/limit-rules/${item.id}`, { method: "PUT", body: payload })
    },
    actions: [
      action("编辑", "ghost", (item) => openEdit(item)),
      action("删除", "danger", (item) => removeItem(`/api/limit-rules/${item.id}`))
    ]
  },
  lists: {
    title: "黑白名单",
    meta: "黑名单拦截，白名单跳过限流",
    path: "/api/blacklists",
    preload: preloadServices,
    filters: [serviceSelect("serviceId", "服务", false, true)],
    customLoad: loadLists,
    columns: [
      ["listKind", "名单"],
      ["serviceId", "服务", serviceName],
      ["type", "类型"],
      ["key", "主体"],
      ["permanent", "永久", boolText],
      ["expiresAt", "过期时间", shortTime]
    ],
    create: {
      title: "新增名单",
      fields: [
        selectField("listKind", "名单类型", [["blacklists", "黑名单"], ["whitelists", "白名单"]]),
        serviceSelect("serviceId", "服务"),
        selectField("type", "主体类型", [["ip", "IP"], ["user", "用户"], ["app", "APP"], ["token", "Token"]]),
        textField("key", "主体值"),
        textAreaField("reason", "原因", false),
        checkboxField("permanent", "永久黑名单", false),
        dateTimeField("expiresAt", "过期时间", false)
      ],
      submit: (payload) => {
        const path = `/${payload.listKind}`;
        delete payload.listKind;
        payload.expiresAt = localDateToRFC3339(payload.expiresAt);
        return api(`/api${path}`, { method: "POST", body: payload });
      }
    },
    actions: [
      action("删除", "danger", (item) => removeItem(`/api/${item.listKind}/${item.id}`))
    ]
  },
  logs: {
    title: "日志查询",
    meta: "操作、鉴权、限流和健康检测日志",
    path: "/api/logs",
    filters: [
      selectField("type", "日志类型", [["operation", "操作"], ["auth", "鉴权"], ["limit", "限流"], ["health", "健康"]]),
      serviceSelect("serviceId", "服务", false, true),
      selectField("result", "结果", [["", "全部"], ["success", "成功"], ["failure", "失败"]], false)
    ],
    create: null,
    columns: [
      ["createdAt", "时间", shortTime],
      ["type", "类型"],
      ["summary", "摘要"],
      ["result", "结果", badge]
    ],
    customLoad: loadLogs,
    actions: []
  },
  statistics: {
    title: "限流统计",
    meta: "按服务、维度和时间查询限流统计",
    path: "/api/limit-statistics",
    preload: preloadServices,
    filters: [
      serviceSelect("serviceId", "服务", false, true),
      selectField("dimension", "维度", [["", "全部"], ["ip", "IP"], ["user_id", "用户"], ["app_id", "APP"], ["path", "接口"]], false)
    ],
    create: null,
    columns: [
      ["bucketTime", "时间", shortTime],
      ["serviceId", "服务", serviceName],
      ["dimension", "维度"],
      ["totalCount", "请求数"],
      ["blockedCount", "拦截数"]
    ],
    actions: []
  },
  health: {
    title: "健康检测",
    meta: "下游服务健康检测日志",
    path: "/api/health-checks",
    preload: preloadServices,
    filters: [
      serviceSelect("serviceId", "服务", false, true)
    ],
    create: null,
    columns: [
      ["createdAt", "时间", shortTime],
      ["serviceId", "服务", serviceName],
      ["status", "状态", badge],
      ["httpStatus", "HTTP"],
      ["latency", "耗时", (v) => `${v || 0}`],
      ["errorMessage", "错误", narrow]
    ],
    actions: []
  }
};

function textField(name, label, required = true, placeholder = "") {
  return { type: fieldTypes.text, name, label, required, placeholder };
}

function passwordField(name, label) {
  return { type: fieldTypes.password, name, label, required: true };
}

function numberField(name, label, required = true) {
  return { type: fieldTypes.number, name, label, required };
}

function urlField(name, label, required = true) {
  return { type: fieldTypes.url, name, label, required };
}

function dateTimeField(name, label, required = false) {
  return { type: fieldTypes.datetime, name, label, required };
}

function checkboxField(name, label, required = false) {
  return { type: fieldTypes.checkbox, name, label, required };
}

function textAreaField(name, label, required = true) {
  return { type: fieldTypes.textarea, name, label, required, wide: true };
}

function selectField(name, label, options, required = true) {
  return { type: fieldTypes.select, name, label, options, required };
}

function multiSelectField(name, label, options) {
  return { type: fieldTypes.multiselect, name, label, options, required: false, wide: true };
}

function serviceSelect(name, label, required = true, includeAll = false) {
  return selectField(name, label, () => {
    const values = state.services.map((service) => [service.id, `${service.name} (${service.code})`]);
    return includeAll ? [["", "全部"], ...values] : values;
  }, required);
}

function limitRuleFields(includeService) {
  const fields = [
    selectField("dimension", "维度", [["ip", "IP"], ["user_id", "用户"], ["app_id", "APP"], ["path", "接口"]]),
    selectField("granularity", "粒度", [["second", "秒"], ["minute", "分钟"], ["hour", "小时"], ["day", "天"]]),
    numberField("capacity", "容量"),
    numberField("ratePerSecond", "每秒令牌"),
    numberField("blacklistHits", "拉黑触发次数", false),
    numberField("blockSeconds", "封禁秒数", false),
    checkboxField("enabled", "启用", false)
  ];
  if (includeService) fields.unshift(serviceSelect("serviceId", "服务"));
  return fields;
}

const statusOptions = [["enabled", "启用"], ["disabled", "禁用"]];

function action(label, className, handler, visible = () => true) {
  return { label, className, handler, visible };
}

function accessToken() {
  return localStorage.getItem(tokenKey) || "";
}

function refreshToken() {
  return localStorage.getItem(refreshKey) || "";
}

function setSession(data) {
  localStorage.setItem(tokenKey, data.accessToken);
  if (data.refreshToken) localStorage.setItem(refreshKey, data.refreshToken);
  el.loginPanel.classList.add("hidden");
  el.workspace.classList.remove("hidden");
  el.logoutBtn.classList.remove("hidden");
  el.sessionState.textContent = "已登录";
}

function clearSession() {
  localStorage.removeItem(tokenKey);
  localStorage.removeItem(refreshKey);
  el.loginPanel.classList.remove("hidden");
  el.workspace.classList.add("hidden");
  el.logoutBtn.classList.add("hidden");
  el.sessionState.textContent = "未登录";
}

async function api(path, options = {}, retried = false) {
  const headers = { ...(options.headers || {}) };
  if (!(options.body instanceof FormData)) headers["Content-Type"] = "application/json";
  if (accessToken()) headers.Authorization = `Bearer ${accessToken()}`;
  const response = await fetch(path, {
    ...options,
    headers,
    body: options.body && !(options.body instanceof FormData) ? JSON.stringify(options.body) : options.body
  });
  const renewed = response.headers.get("X-Access-Token");
  if (renewed) localStorage.setItem(tokenKey, renewed);
  const text = await response.text();
  const body = text ? JSON.parse(text) : {};
  if (response.status === 401 && refreshToken() && !retried) {
    await refreshSession();
    return api(path, options, true);
  }
  if (!response.ok) throw new Error(body.message || response.statusText);
  return body.data ?? body;
}

async function refreshSession() {
  const data = await api("/api/auth/refresh", {
    method: "POST",
    body: { refreshToken: refreshToken() }
  }, true);
  setSession(data);
}

function renderTabs() {
  el.tabs.innerHTML = "";
  Object.entries(views).forEach(([key, view]) => {
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.view = key;
    button.textContent = view.title;
    button.classList.toggle("active", key === state.currentView);
    el.tabs.appendChild(button);
  });
}

async function loadView(viewKey = state.currentView) {
  state.currentView = viewKey;
  const view = views[viewKey];
  renderTabs();
  el.title.textContent = view.title;
  el.meta.textContent = view.meta || "";
  el.createBtn.classList.toggle("hidden", !view.create);
  hideAlert();
  renderFilters(view);
  if (view.preload) await view.preload();
  const rows = view.customLoad ? await view.customLoad(view) : await api(queryPath(view.path));
  state.data[viewKey] = Array.isArray(rows) ? rows : [];
  renderTable(view, state.data[viewKey]);
}

function renderFilters(view) {
  el.filterForm.innerHTML = "";
  (view.filters || []).forEach((field) => {
    el.filterForm.appendChild(renderField(field, {}));
  });
  if ((view.filters || []).length > 0) {
    const button = document.createElement("button");
    button.type = "submit";
    button.textContent = "筛选";
    el.filterForm.appendChild(button);
  }
  el.filterForm.classList.toggle("hidden", (view.filters || []).length === 0);
}

function queryPath(basePath) {
  const params = new URLSearchParams();
  new FormData(el.filterForm).forEach((value, key) => {
    if (value !== "") params.set(key, value);
  });
  const query = params.toString();
  return query ? `${basePath}?${query}` : basePath;
}

function renderTable(view, rows) {
  const columns = [...view.columns, ["__actions", "操作"]];
  el.tableHead.innerHTML = `<tr>${columns.map(([, label]) => `<th>${escapeHtml(label)}</th>`).join("")}</tr>`;
  if (!rows.length) {
    el.tableBody.innerHTML = `<tr><td colspan="${columns.length}">暂无数据</td></tr>`;
    return;
  }
  el.tableBody.innerHTML = "";
  rows.forEach((row) => {
    const tr = document.createElement("tr");
    columns.forEach(([key, , formatter]) => {
      const td = document.createElement("td");
      if (key === "__actions") {
        td.appendChild(renderActions(view, row));
      } else {
        td.innerHTML = formatter ? formatter(row[key], row) : escapeHtml(row[key] ?? "");
      }
      tr.appendChild(td);
    });
    el.tableBody.appendChild(tr);
  });
}

function renderActions(view, item) {
  const wrap = document.createElement("div");
  wrap.className = "row-actions";
  (view.actions || []).forEach((act) => {
    if (!act.visible(item)) return;
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = act.label;
    button.className = act.className || "ghost";
    button.addEventListener("click", () => act.handler(item));
    wrap.appendChild(button);
  });
  return wrap;
}

function openCreate() {
  const view = views[state.currentView];
  openForm(view.create.title, view.create.fields, {}, async (payload) => {
    const result = await view.create.submit(payload);
    if (view.create.after) view.create.after(result);
    await loadView();
  });
}

function openEdit(item) {
  const view = views[state.currentView];
  openForm(view.edit.title, view.edit.fields, item, async (payload) => {
    await view.edit.submit(item, payload);
    await loadView();
  });
}

function openForm(title, fields, item, onSubmit) {
  el.modalTitle.textContent = title;
  el.modalBody.innerHTML = "";
  fields.forEach((field) => el.modalBody.appendChild(renderField(field, item)));
  el.modalForm.onsubmit = async (event) => {
    event.preventDefault();
    try {
      const payload = formPayload(el.modalForm, fields);
      await onSubmit(payload);
      closeModal();
      showAlert("操作成功");
    } catch (error) {
      showAlert(error.message, true);
    }
  };
  el.modal.showModal();
}

function renderField(field, item) {
  const label = document.createElement("label");
  if (field.wide) label.classList.add("field-wide");
  label.textContent = field.label;
  let control;
  if (field.type === fieldTypes.textarea) {
    control = document.createElement("textarea");
  } else if (field.type === fieldTypes.select || field.type === fieldTypes.multiselect) {
    control = document.createElement("select");
    if (field.type === fieldTypes.multiselect) control.multiple = true;
    optionValues(field).forEach(([value, text]) => {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = text;
      control.appendChild(option);
    });
  } else {
    control = document.createElement("input");
    control.type = field.type;
  }
  control.name = field.name;
  control.required = !!field.required;
  if (field.placeholder) control.placeholder = field.placeholder;
  setControlValue(control, field, item[field.name]);
  label.appendChild(control);
  return label;
}

function optionValues(field) {
  return typeof field.options === "function" ? field.options() : field.options;
}

function setControlValue(control, field, value) {
  if (field.type === fieldTypes.checkbox) {
    control.checked = value === undefined ? true : !!value;
    return;
  }
  if (field.type === fieldTypes.multiselect) {
    const selected = new Set(value || []);
    [...control.options].forEach((option) => {
      option.selected = selected.has(option.value);
    });
    return;
  }
  if (field.type === fieldTypes.datetime && value) {
    control.value = value.slice(0, 16);
    return;
  }
  control.value = value ?? "";
}

function formPayload(form, fields) {
  const payload = {};
  fields.forEach((field) => {
    const control = form.elements[field.name];
    if (!control) return;
    if (field.type === fieldTypes.checkbox) {
      payload[field.name] = control.checked;
    } else if (field.type === fieldTypes.multiselect) {
      payload[field.name] = [...control.selectedOptions].map((option) => option.value);
    } else if (field.type === fieldTypes.number) {
      payload[field.name] = control.value === "" ? 0 : Number(control.value);
    } else {
      payload[field.name] = control.value;
    }
  });
  return payload;
}

async function updateUserStatus(item, status) {
  await api(`/api/users/${item.id}/status`, { method: "PUT", body: { status } });
  showAlert("用户状态已更新");
  await loadView();
}

function openPassword(item) {
  openForm("修改密码", [passwordField("newPassword", "新密码")], {}, async (payload) => {
    await api(`/api/users/${item.id}/password`, { method: "PUT", body: payload });
    await loadView();
  });
}

function openRoleAssign(kind, item) {
  openForm("分配角色", [multiSelectField("roleIds", "角色", () => state.roles.map((role) => [role.id, `${role.code} ${role.name}`]))], { roleIds: roleIds(item) }, async (payload) => {
    const base = kind === "user" ? "users" : "apps";
    await api(`/api/${base}/${item.id}/roles`, { method: "PUT", body: payload });
    await loadView();
  });
}

async function resetAppSecret(item) {
  const result = await api(`/api/apps/${item.id}/reset-secret`, { method: "POST", body: {} });
  showSecret("AppSecret", "appSecret")(result);
}

async function resetOIDCSecret(item) {
  const result = await api(`/api/oidc-clients/${item.id}/reset-secret`, { method: "POST", body: {} });
  showSecret("ClientSecret", "clientSecret")(result);
}

async function approveService(item) {
  await api(`/api/services/${item.id}/approve`, { method: "POST", body: {} });
  showAlert("服务已审核");
  await loadView();
}

async function removeItem(path) {
  if (!confirm("确认删除？")) return;
  await api(path, { method: "DELETE" });
  showAlert("已删除");
  await loadView();
}

async function preloadRoles() {
  const [roles, permissions] = await Promise.all([api("/api/roles"), api("/api/permissions")]);
  state.roles = roles;
  state.permissions = permissions;
}

async function preloadServices() {
  state.services = await api("/api/services");
}

async function loadLists() {
  const params = new URLSearchParams();
  new FormData(el.filterForm).forEach((value, key) => {
    if (value !== "") params.set(key, value);
  });
  const query = params.toString();
  const suffix = query ? `?${query}` : "";
  const [blacklists, whitelists] = await Promise.all([
    api(`/api/blacklists${suffix}`),
    api(`/api/whitelists${suffix}`)
  ]);
  return [
    ...blacklists.map((item) => ({ ...item, listKind: "blacklists" })),
    ...whitelists.map((item) => ({ ...item, listKind: "whitelists", permanent: false }))
  ];
}

async function loadLogs() {
  const data = await api(queryPath("/api/logs"));
  const type = data.type || "operation";
  return (data.items || []).map((item) => ({ ...item, type, summary: logSummary(type, item) }));
}

function logSummary(type, item) {
  if (type === "operation") return `${item.actorType || ""} ${item.action || ""} ${item.resource || ""}`;
  if (type === "auth") return `${item.subjectType || ""} ${item.event || ""} ${item.reason || ""}`;
  if (type === "limit") return `${item.dimension || ""} ${item.key || ""}`;
  return `${item.status || ""} ${item.errorMessage || ""}`;
}

function showSecret(label, key) {
  return (result) => {
    const secret = result[key];
    if (!secret) return;
    showAlert(`${label} 仅显示一次`);
    el.modalTitle.textContent = label;
    el.modalBody.innerHTML = `<div class="secret-box">${escapeHtml(secret)}</div>`;
    el.modalForm.onsubmit = (event) => event.preventDefault();
    el.modal.showModal();
  };
}

function roleIds(item) {
  if (item.roleIds) return item.roleIds;
  const codes = new Set(item.roles || []);
  return state.roles.filter((role) => codes.has(role.code)).map((role) => role.id);
}

function closeModal() {
  el.modal.close();
}

function showAlert(message, error = false) {
  el.alert.textContent = message;
  el.alert.classList.toggle("error", error);
  el.alert.classList.remove("hidden");
}

function hideAlert() {
  el.alert.classList.add("hidden");
  el.alert.classList.remove("error");
}

function shortTime(value) {
  if (!value) return "";
  return escapeHtml(String(value).replace("T", " ").replace("Z", ""));
}

function listText(value) {
  return escapeHtml((value || []).join(", "));
}

function permissionText(value) {
  return escapeHtml((value || []).map((item) => item.code || item).join(", "));
}

function boolText(value) {
  return value ? '<span class="badge ok">是</span>' : '<span class="badge">否</span>';
}

function badge(value) {
  const text = escapeHtml(value ?? "");
  const kind = ["enabled", "approved", "healthy", "success"].includes(value)
    ? "ok"
    : ["pending", "degraded", "unknown"].includes(value)
      ? "warn"
      : ["disabled", "offline", "unhealthy", "failure"].includes(value)
        ? "bad"
        : "";
  return `<span class="badge ${kind}">${text}</span>`;
}

function serviceName(value) {
  const service = state.services.find((item) => item.id === value);
  return escapeHtml(service ? `${service.name} (${service.code})` : value || "");
}

function narrow(value) {
  return `<span title="${escapeHtml(value ?? "")}">${escapeHtml(value ?? "")}</span>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function localDateToRFC3339(value) {
  if (!value) return null;
  const date = new Date(value);
  return date.toISOString();
}

el.loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  el.loginMessage.textContent = "";
  try {
    const data = await api("/api/auth/login", {
      method: "POST",
      body: {
        username: document.querySelector("#username").value,
        password: document.querySelector("#password").value
      }
    });
    setSession(data);
    await loadView();
  } catch (error) {
    el.loginMessage.textContent = error.message;
  }
});

el.tabs.addEventListener("click", async (event) => {
  if (event.target.matches("button[data-view]")) {
    await loadView(event.target.dataset.view);
  }
});

el.refreshBtn.addEventListener("click", () => loadView());
el.createBtn.addEventListener("click", openCreate);
el.filterForm.addEventListener("submit", (event) => {
  event.preventDefault();
  loadView();
});
el.modalCancel.addEventListener("click", closeModal);
el.modalClose.addEventListener("click", closeModal);
el.logoutBtn.addEventListener("click", async () => {
  try {
    if (accessToken() && refreshToken()) {
      await api("/api/auth/logout", { method: "POST", body: { refreshToken: refreshToken() } });
    }
  } catch (_) {
    // Local session cleanup still matters if the server already revoked the token.
  }
  clearSession();
});

renderTabs();
if (accessToken()) {
  setSession({ accessToken: accessToken(), refreshToken: refreshToken() });
  loadView().catch((error) => {
    showAlert(error.message, true);
  });
} else {
  clearSession();
}
