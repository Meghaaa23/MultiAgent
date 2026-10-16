// Dev-server proxy for `ng serve`. Forwards /api -> the FastAPI backend and,
// when API_AUTH_TOKEN is set in the serve-time environment, injects the
// matching `Authorization: Bearer <token>` header into every proxied request.
//
// This keeps the token out of the browser bundle and out of git: it lives only
// in the shell that launches `ng serve`, mirroring the backend's own env var.
//   export API_AUTH_TOKEN="dev-local-token"   # same value the backend uses
//   ng serve
//
// If the env var is unset, no header is added (the backend then responds 503,
// matching its fail-closed behavior) rather than sending an empty/invalid one.
const token = (process.env.API_AUTH_TOKEN || '').trim();

const proxy = {
  '/api': {
    target: 'http://localhost:8001',
    secure: false,
    changeOrigin: true,
    pathRewrite: { '^/api': '' },
    // No timeout: a scan's SSE stream stays open until the backend finishes the
    // crawl on its own. The backend governs duration (SCAN_TIMEOUT_SECONDS);
    // the dev proxy must not cut a long-running scan short.
    timeout: 0,
    proxyTimeout: 0,
    logLevel: 'info',
  },
};

if (token) {
  proxy['/api'].headers = { Authorization: `Bearer ${token}` };
} else {
  console.warn(
    '[proxy] API_AUTH_TOKEN is not set — proxied /api requests will be ' +
      'unauthenticated and the backend will respond 503. Export it before ' +
      '`ng serve` to inject the Bearer header.',
  );
}

module.exports = proxy;
