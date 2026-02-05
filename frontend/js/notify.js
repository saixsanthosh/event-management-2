(function () {
  if (window.showNotice) return;

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
})();
