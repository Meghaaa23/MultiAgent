(function () {
  if (window.__VENDOR_CHAT_LOADED) return;
  window.__VENDOR_CHAT_LOADED = true;

  var host = (document.currentScript && document.currentScript.src)
    ? new URL(document.currentScript.src).origin
    : "http://vendor.chat.local:3130";

  var bubble = document.createElement("button");
  bubble.type = "button";
  bubble.setAttribute("aria-label", "Chat with support");
  bubble.textContent = "Chat";
  bubble.style.cssText = "position:fixed;right:16px;bottom:16px;z-index:99999;background:#4f46e5;color:#fff;border:0;border-radius:999px;padding:12px 18px;cursor:pointer;font:600 14px system-ui";

  var panel = document.createElement("iframe");
  panel.src = host + "/embed.html";
  panel.title = "Vendor chat";
  panel.style.cssText = "position:fixed;right:16px;bottom:64px;width:320px;height:380px;border:1px solid #ddd;border-radius:8px;display:none;z-index:99999;background:#fff";

  bubble.addEventListener("click", function () {
    panel.style.display = panel.style.display === "none" ? "block" : "none";
  });

  document.addEventListener("DOMContentLoaded", function () {
    document.body.appendChild(bubble);
    document.body.appendChild(panel);
  });
  if (document.readyState !== "loading") {
    document.body.appendChild(bubble);
    document.body.appendChild(panel);
  }
})();
