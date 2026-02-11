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
   NON-BLOCKING MODALS
========================= */
if (!window.uiPrompt) {
  window.uiPrompt = function uiPrompt({ title, message, defaultValue = "", placeholder = "" }) {
    return new Promise((resolve) => {
      const backdrop = document.createElement("div");
      backdrop.className = "modal-backdrop";
      backdrop.innerHTML = `
        <div class="modal-card" role="dialog" aria-modal="true">
          <div class="modal-title">${title || "Input Required"}</div>
          <div class="modal-message">${message || ""}</div>
          <input class="modal-input" placeholder="${placeholder}" value="${String(defaultValue)}" />
          <div class="modal-actions">
            <button class="login-btn" data-action="cancel" type="button">Cancel</button>
            <button class="login-btn" data-action="ok" type="button">OK</button>
          </div>
        </div>
      `;
      document.body.appendChild(backdrop);

      const input = backdrop.querySelector(".modal-input");
      const okBtn = backdrop.querySelector('[data-action="ok"]');
      const cancelBtn = backdrop.querySelector('[data-action="cancel"]');

      const cleanup = (value) => {
        backdrop.remove();
        resolve(value);
      };

      okBtn.addEventListener("click", () => cleanup(input.value));
      cancelBtn.addEventListener("click", () => cleanup(null));
      backdrop.addEventListener("click", (e) => {
        if (e.target === backdrop) cleanup(null);
      });
      input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") cleanup(input.value);
        if (e.key === "Escape") cleanup(null);
      });

      setTimeout(() => input.focus(), 0);
    });
  };
}

if (!window.uiConfirm) {
  window.uiConfirm = function uiConfirm({ title, message }) {
    return new Promise((resolve) => {
      const backdrop = document.createElement("div");
      backdrop.className = "modal-backdrop";
      backdrop.innerHTML = `
        <div class="modal-card" role="dialog" aria-modal="true">
          <div class="modal-title">${title || "Confirm"}</div>
          <div class="modal-message">${message || "Are you sure?"}</div>
          <div class="modal-actions">
            <button class="login-btn" data-action="cancel" type="button">Cancel</button>
            <button class="login-btn" data-action="ok" type="button">Confirm</button>
          </div>
        </div>
      `;
      document.body.appendChild(backdrop);

      const okBtn = backdrop.querySelector('[data-action="ok"]');
      const cancelBtn = backdrop.querySelector('[data-action="cancel"]');

      const cleanup = (value) => {
        backdrop.remove();
        resolve(value);
      };

      okBtn.addEventListener("click", () => cleanup(true));
      cancelBtn.addEventListener("click", () => cleanup(false));
      backdrop.addEventListener("click", (e) => {
        if (e.target === backdrop) cleanup(false);
      });
      window.addEventListener(
        "keydown",
        (e) => {
          if (e.key === "Escape") cleanup(false);
        },
        { once: true }
      );
    });
  };
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
const themeToggleIcon = themeToggle ? themeToggle.querySelector("i") : null;

function updateThemeIcon(theme) {
  if (!themeToggleIcon) return;
  if (theme === "dark") {
    themeToggleIcon.classList.remove("fa-moon");
    themeToggleIcon.classList.add("fa-sun");
  } else {
    themeToggleIcon.classList.remove("fa-sun");
    themeToggleIcon.classList.add("fa-moon");
  }
}

updateThemeIcon(document.documentElement.getAttribute("data-theme") || "dark");

if (themeToggle) {
  themeToggle.addEventListener("click", () => {
    const html = document.documentElement;
    const theme =
      html.getAttribute("data-theme") === "dark" ? "light" : "dark";
    html.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
    updateThemeIcon(theme);
    window.dispatchEvent(new Event("theme:changed"));
  });
}

/* =========================
   GLOBAL BACK BUTTON
========================= */
(function initBackButton() {
  const path = (window.location.pathname || "").toLowerCase();
  const trimmedPath = path.replace(/\/+$/, "");
  const currentFile = trimmedPath.split("/").pop() || "";
  const isMainPage = !trimmedPath || currentFile === "index.html";
  if (isMainPage) return;

  if (!document.body || document.querySelector(".nav-back-btn")) return;

  const backBtn = document.createElement("button");
  backBtn.type = "button";
  backBtn.className = "nav-back-btn";
  backBtn.setAttribute("aria-label", "Go back");
  backBtn.setAttribute("title", "Go back");
  backBtn.innerHTML = '<i class="fas fa-arrow-left" aria-hidden="true"></i>';

  function hasInternalReferrer() {
    if (!document.referrer) return false;
    try {
      return new URL(document.referrer).origin === window.location.origin;
    } catch (err) {
      return false;
    }
  }

  backBtn.addEventListener("click", () => {
    if (hasInternalReferrer()) {
      window.history.back();
      return;
    }
    window.location.href = `${API_BASE}/index.html`;
  });

  document.body.appendChild(backBtn);
})();

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

/* =========================
   ANIMATED BACKGROUND (DOT GLOBE)
========================= */
(function initAnimatedBackground() {
  const container = document.querySelector(".bg-animation");
  if (!container) return;

  if (container.querySelector(".bg-canvas")) return;

  const canvas = document.createElement("canvas");
  canvas.className = "bg-canvas";
  container.appendChild(canvas);

  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const reducedMotion =
    window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  let width = 0;
  let height = 0;
  let dpr = window.devicePixelRatio || 1;
  const points = [];
  let themeColors = null;
  const pointer = {
    x: 0.5,
    y: 0.5,
    targetX: 0.5,
    targetY: 0.5
  };
  let pointerActive = false;
  let pointerType = "mouse";
  let lastPointerInputAt = 0;
  const interactionFadeMs = 2200;
  const desktopSceneConfig = {
    pointMin: 2600,
    pointMax: 7000,
    densityDivisor: 380,
    sizeBase: 2.4,
    sizeRange: 3.6,
    alphaBase: 0.08,
    alphaRange: 0.28
  };
  const mobileSceneConfig = {
    pointMin: 1300,
    pointMax: 2800,
    densityDivisor: 500,
    sizeBase: 1.85,
    sizeRange: 2.6,
    alphaBase: 0.05,
    alphaRange: 0.23
  };
  let sceneConfig = desktopSceneConfig;
  let isMobileScene = false;
  let lastFrameAt = 0;
  let frameHandle = null;

  function refreshSceneConfig() {
    const isMobile =
      window.matchMedia &&
      window.matchMedia("(max-width: 900px), (pointer: coarse)").matches;
    isMobileScene = Boolean(isMobile);
    sceneConfig = isMobile ? mobileSceneConfig : desktopSceneConfig;
  }

  function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
  }

  function setPointerFromClient(clientX, clientY, inputType = "mouse") {
    const rect = container.getBoundingClientRect();
    const nextX = (clientX - rect.left) / Math.max(1, rect.width);
    const nextY = (clientY - rect.top) / Math.max(1, rect.height);
    pointer.targetX = clamp(nextX, 0, 1);
    pointer.targetY = clamp(nextY, 0, 1);
    pointerActive = true;
    pointerType = inputType || "mouse";
    lastPointerInputAt = performance.now();
    queueFrame();
  }

  function releasePointer() {
    pointerActive = false;
    queueFrame();
  }

  function queueFrame() {
    if (frameHandle !== null) return;
    frameHandle = requestAnimationFrame((nextTime) => {
      frameHandle = null;
      draw(nextTime);
    });
  }

  function resize() {
    refreshSceneConfig();
    width = container.clientWidth || window.innerWidth;
    height = container.clientHeight || window.innerHeight;
    const rawDpr = window.devicePixelRatio || 1;
    dpr = isMobileScene ? Math.min(1.8, rawDpr) : rawDpr;

    canvas.width = width * dpr;
    canvas.height = height * dpr;
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function parseColor(input, fallback) {
    const value = String(input || "").trim();
    if (!value) return fallback;
    if (value.startsWith("#")) {
      const hex = value.replace("#", "");
      if (hex.length === 3) {
        const r = parseInt(hex[0] + hex[0], 16);
        const g = parseInt(hex[1] + hex[1], 16);
        const b = parseInt(hex[2] + hex[2], 16);
        return [r, g, b];
      }
      if (hex.length === 6) {
        const r = parseInt(hex.slice(0, 2), 16);
        const g = parseInt(hex.slice(2, 4), 16);
        const b = parseInt(hex.slice(4, 6), 16);
        return [r, g, b];
      }
    }
    const rgba = value.match(/rgba?\(([^)]+)\)/);
    if (rgba) {
      const parts = rgba[1].split(",").map((v) => Number.parseFloat(v.trim()));
      return [parts[0] || fallback[0], parts[1] || fallback[1], parts[2] || fallback[2]];
    }
    return fallback;
  }

  function refreshThemeColors() {
    const styles = getComputedStyle(document.documentElement);
    const dotPrimary = parseColor(styles.getPropertyValue("--dot-primary"), [176, 144, 255]);
    const dotSecondary = parseColor(styles.getPropertyValue("--dot-secondary"), [120, 76, 255]);
    const accent = parseColor(styles.getPropertyValue("--accent-color"), [139, 92, 246]);
    themeColors = {
      dotPrimary,
      dotSecondary,
      accent
    };
  }

  function smoothstep(edge0, edge1, x) {
    const t = Math.max(0, Math.min(1, (x - edge0) / (edge1 - edge0)));
    return t * t * (3 - 2 * t);
  }

  function buildScene() {
    refreshSceneConfig();
    points.length = 0;
    const pointCount = Math.min(
      sceneConfig.pointMax,
      Math.max(sceneConfig.pointMin, Math.floor((width * height) / sceneConfig.densityDivisor))
    );
    for (let i = 0; i < pointCount; i += 1) {
      const u = Math.random();
      const v = Math.random();
      const theta = u * Math.PI * 2;
      const phi = Math.acos(2 * v - 1);
      const r = Math.cbrt(Math.random());

      const sinPhi = Math.sin(phi);
      const x = r * sinPhi * Math.cos(theta);
      const y = r * Math.cos(phi);
      const z = r * sinPhi * Math.sin(theta);

      points.push({
        x,
        y,
        z,
        size: sceneConfig.sizeBase + Math.random() * sceneConfig.sizeRange,
        alpha: sceneConfig.alphaBase + Math.random() * sceneConfig.alphaRange,
        jitter: Math.random() * Math.PI * 2
      });
    }
  }

  function draw(time) {
    ctx.clearRect(0, 0, width, height);

    const frameDelta = lastFrameAt ? Math.min(50, Math.max(8, time - lastFrameAt)) : 16.67;
    lastFrameAt = time;
    const frameScale = frameDelta / 16.67;
    const t = time * 0.001;
    const isTouchInput = pointerType === "touch";
    const followLerpBase = isTouchInput ? 0.11 : 0.08;
    const returnLerpBase = isTouchInput ? 0.04 : 0.035;
    const followLerp = 1 - Math.pow(1 - followLerpBase, frameScale);
    const returnLerp = 1 - Math.pow(1 - returnLerpBase, frameScale);
    const sensitivity = isTouchInput ? 0.62 : 0.92;
    const inactiveFor = performance.now() - lastPointerInputAt;
    const interactionStrength = pointerActive
      ? 1
      : clamp(1 - inactiveFor / interactionFadeMs, 0, 1);
    const scaledStrength = interactionStrength * sensitivity;

    if (!pointerActive) {
      pointer.targetX += (0.5 - pointer.targetX) * returnLerp;
      pointer.targetY += (0.5 - pointer.targetY) * returnLerp;
    }

    pointer.x += (pointer.targetX - pointer.x) * followLerp;
    pointer.y += (pointer.targetY - pointer.y) * followLerp;

    const pointerX = (pointer.x - 0.5) * 2;
    const pointerY = (pointer.y - 0.5) * 2;
    // Cursor/touch follow uses direct mapping; tilt uses opposite sign for natural depth.
    const followX = pointerX;
    const followY = pointerY;
    const tiltX = -pointerX;
    const tiltY = -pointerY;

    if (!themeColors) refreshThemeColors();

    const cx =
      width * 0.5 +
      Math.sin(t * 0.18) * width * 0.04 +
      followX * width * 0.065 * scaledStrength;
    const cy =
      height * 0.52 +
      Math.cos(t * 0.15) * height * 0.03 +
      followY * height * 0.05 * scaledStrength;
    const radius = Math.min(width, height) * 1.8;
    const rotY =
      t * 0.18 +
      Math.sin(t * 0.32) * 0.35 +
      tiltX * 0.52 * scaledStrength;
    const rotX =
      t * 0.14 +
      Math.cos(t * 0.26) * 0.3 +
      tiltY * 0.42 * scaledStrength;
    const rotZ =
      t * 0.12 +
      Math.sin(t * 0.22) * 0.25 +
      (tiltX - tiltY) * 0.16 * scaledStrength;

    const cosY = Math.cos(rotY);
    const sinY = Math.sin(rotY);
    const cosX = Math.cos(rotX);
    const sinX = Math.sin(rotX);
    const cosZ = Math.cos(rotZ);
    const sinZ = Math.sin(rotZ);

    ctx.save();
    ctx.globalCompositeOperation = "screen";

    const [r, g, b] = themeColors.dotPrimary;
    const [r2, g2, b2] = themeColors.dotSecondary;

    points.forEach((point) => {
      const wobble = 0.01 * Math.sin(t * 1.1 + point.jitter);
      let x = point.x * (1 + wobble);
      let y = point.y * (1 + wobble);
      let z = point.z * (1 + wobble);

      const dx = x * cosY - z * sinY;
      const dz = x * sinY + z * cosY;
      const dy = y * cosX - dz * sinX;
      const dz2 = y * sinX + dz * cosX;

      const dx2 = dx * cosZ - dy * sinZ;
      const dy2 = dx * sinZ + dy * cosZ;

      const depth = (dz2 + 1.3) / 2.6;
      const perspective = 1 / (1.6 - dz2 * 0.8);
      const scale = radius * perspective;
      const radial = (Math.hypot(dx2, dy2) * scale) / radius;
      if (radial > 1.08) return;
      const edgeSoft = 1 - smoothstep(0.72, 1.05, radial);

      const sx = dx2 * scale + cx;
      const sy = dy2 * scale + cy;

      const size = Math.round(point.size * (0.9 + depth * 1.6) * (0.6 + edgeSoft * 0.8));
      const alpha = point.alpha * (0.14 + depth * 0.8) * (0.2 + edgeSoft * 0.9);

      const color = dz2 > 0 ? [r, g, b] : [r2, g2, b2];
      ctx.fillStyle = `rgba(${color[0]}, ${color[1]}, ${color[2]}, ${alpha})`;
      ctx.fillRect(Math.round(sx), Math.round(sy), size, size);
    });

    ctx.restore();

    if (!reducedMotion || pointerActive || interactionStrength > 0.001) {
      queueFrame();
    }
  }

  resize();
  buildScene();
  refreshThemeColors();

  if (window.PointerEvent) {
    window.addEventListener(
      "pointermove",
      (event) => setPointerFromClient(event.clientX, event.clientY, event.pointerType || "mouse"),
      { passive: true }
    );
    window.addEventListener(
      "pointerdown",
      (event) => setPointerFromClient(event.clientX, event.clientY, event.pointerType || "mouse"),
      { passive: true }
    );
    window.addEventListener("pointerup", releasePointer, { passive: true });
    window.addEventListener("pointercancel", releasePointer, { passive: true });
  } else {
    window.addEventListener(
      "mousemove",
      (event) => setPointerFromClient(event.clientX, event.clientY, "mouse"),
      { passive: true }
    );
    window.addEventListener(
      "touchstart",
      (event) => {
        const touch = event.touches && event.touches[0];
        if (touch) setPointerFromClient(touch.clientX, touch.clientY, "touch");
      },
      { passive: true }
    );
    window.addEventListener(
      "touchmove",
      (event) => {
        const touch = event.touches && event.touches[0];
        if (touch) setPointerFromClient(touch.clientX, touch.clientY, "touch");
      },
      { passive: true }
    );
    window.addEventListener("touchend", releasePointer, { passive: true });
    window.addEventListener("touchcancel", releasePointer, { passive: true });
  }

  document.addEventListener("mouseleave", releasePointer, { passive: true });
  window.addEventListener("blur", releasePointer);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState !== "visible") releasePointer();
  });

  window.addEventListener("resize", () => {
    resize();
    buildScene();
    queueFrame();
  });

  window.addEventListener("theme:changed", () => {
    refreshThemeColors();
    queueFrame();
  });

  queueFrame();
})();
