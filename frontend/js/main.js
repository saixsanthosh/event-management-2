const API_BASE = window.location.origin;

/* =========================
   NOTIFICATIONS
========================= */
if (!window.showNotice) {
  const NOTICE_COLORS = {
    success: "#38a169",
    error: "#e53e3e",
    info: "#3182ce"
  };

  function inferNoticeType(message) {
    const msg = String(message).toLowerCase();
    const successWords = [
      "success",
      "created",
      "updated",
      "deleted",
      "submitted",
      "uploaded",
      "sent",
      "verified",
      "approved",
      "rejected",
      "copied",
      "saved"
    ];
    const errorWords = [
      "fail",
      "error",
      "invalid",
      "denied",
      "required",
      "not reachable",
      "missing",
      "unauthorized",
      "forbidden"
    ];

    if (successWords.some((w) => msg.includes(w))) return "success";
    if (errorWords.some((w) => msg.includes(w))) return "error";
    return "info";
  }

  function ensureNoticeContainer() {
    let container = document.getElementById("toast-container");
    if (container) return container;
    container = document.createElement("div");
    container.id = "toast-container";
    Object.assign(container.style, {
      position: "fixed",
      top: "20px",
      right: "20px",
      zIndex: "9999",
      display: "flex",
      flexDirection: "column",
      gap: "10px",
      maxWidth: "360px"
    });
    document.body.appendChild(container);
    return container;
  }

  function showNotice(message, type = "info") {
    try {
      const container = ensureNoticeContainer();
      const color = NOTICE_COLORS[type] || NOTICE_COLORS.info;
      const toast = document.createElement("div");
      Object.assign(toast.style, {
        border: "1px solid var(--border-color)",
        borderLeft: `6px solid ${color}`,
        background: "var(--input-bg)",
        color: "var(--text-primary)",
        padding: "12px 14px",
        borderRadius: "12px",
        boxShadow: "0 8px 20px rgba(0,0,0,0.12)",
        fontSize: "0.95rem",
        display: "flex",
        gap: "10px",
        alignItems: "center",
        opacity: "0",
        transform: "translateY(-6px)",
        transition: "opacity 0.2s ease, transform 0.2s ease"
      });

      const label =
        type === "success" ? "Success" : type === "error" ? "Error" : "Info";
      toast.innerHTML = `<span style="font-weight:700;color:${color}">${label}</span><span style="line-height:1.2">${message}</span>`;
      container.appendChild(toast);

      requestAnimationFrame(() => {
        toast.style.opacity = "1";
        toast.style.transform = "translateY(0)";
      });

      setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateY(-6px)";
        setTimeout(() => toast.remove(), 200);
      }, 3200);
    } catch (err) {
      if (window.__nativeAlert) {
        window.__nativeAlert(message);
      }
    }
  }

  window.showNotice = showNotice;
  window.showSuccess = (msg) => showNotice(msg, "success");
  window.showError = (msg) => showNotice(msg, "error");
  window.showInfo = (msg) => showNotice(msg, "info");

  if (!window.__nativeAlert) {
    window.__nativeAlert = window.alert;
  }
  window.alert = (msg) => showNotice(msg, inferNoticeType(msg));
}

/* =========================
   DASHBOARD MAP
========================= */
const dashboardMap = {
  President: "dashboard/president.html",
  Faculty: "dashboard/faculty.html",
  HOD: "dashboard/hod.html",
  VP: "dashboard/vp.html",
  Dean: "dashboard/dean.html",
  Coordinator: "dashboard/coordinator.html",
  Volunteer: "dashboard/volunteer.html"
};

/* =========================
   THEME TOGGLE
========================= */
const savedTheme = localStorage.getItem("theme");
if (savedTheme === "dark" || savedTheme === "light") {
  document.documentElement.setAttribute("data-theme", savedTheme);
}

const themeToggle = document.getElementById("themeToggle");
if (themeToggle) {
  themeToggle.addEventListener("click", () => {
    const html = document.documentElement;
    const theme =
      html.getAttribute("data-theme") === "dark" ? "light" : "dark";
    html.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  });
}

/* =========================
   PASSWORD TOGGLE
========================= */
const passwordToggle = document.getElementById("passwordToggle");
if (passwordToggle) {
  passwordToggle.addEventListener("click", () => {
    const pwd = document.getElementById("password");
    pwd.type = pwd.type === "password" ? "text" : "password";
  });
}

/* =========================
   LOGIN FORM
========================= */
const loginForm = document.getElementById("loginForm");
const errorMessage = document.getElementById("errorMessage");

if (loginForm) {
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value.trim();

    try {
      const res = await fetch(`${API_BASE}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });

      const data = await res.json();

      if (!data.success) {
        showError("Invalid username or password");
        return;
      }

      // ✅ SAVE TOKEN + USER
      localStorage.setItem("token", data.token);
      localStorage.setItem("user", JSON.stringify(data.user));

      // ROLE → DASHBOARD
      const dashboard = dashboardMap[data.user.role];
      window.location.href = dashboard;

    } catch (err) {
      console.error(err);
      alert("Backend not reachable");
    }
  });
}

/* =========================
   ERROR HANDLER
========================= */
function showError(msg) {
  if (errorMessage) {
    errorMessage.style.display = "flex";
    errorMessage.querySelector("span").innerText = msg;
  }
}
