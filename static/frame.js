'use strict';
(() => {
  const mainOrigin = document.documentElement.dataset.mainOrigin;
  const adminOrigin = document.documentElement.dataset.adminOrigin;
  const gate = document.getElementById('keymgr-auth-gate');
  const status = document.getElementById('keymgr-auth-status');
  const panel = document.getElementById('keymgr-panel');
  const pending = new Set();
  let generation = 0;

  function readToken() {
    try { return localStorage.getItem('auth_token') || ''; }
    catch { return ''; }
  }

  function lock(message) {
    generation++;
    for (const controller of pending) controller.abort();
    pending.clear();
    panel.replaceChildren(); panel.hidden = true; gate.hidden = false;
    status.textContent = message || '请先在主站以管理员身份登录。';
    window.dispatchEvent(new CustomEvent('keymgr:logout'));
  }

  // Every management request reads the current main-site token afresh.
  // No bearer token is sent to the parent/admin origin or stored by this page.
  window.keymgrFetch = async function(path, options = {}) {
    if (location.origin !== mainOrigin) throw new Error('页面来源无效。');
    const target = new URL(path, mainOrigin);
    if (target.origin !== mainOrigin || !target.pathname.startsWith('/__keymgr/api/')) {
      throw new Error('请求地址无效。');
    }
    const token = readToken();
    if (!token) { lock('主站已退出登录。'); throw new Error('请先登录主站。'); }
    const controller = new AbortController();
    const headers = new Headers(options.headers || {});
    headers.set('Authorization', 'Bearer ' + token);
    if (options.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    const abort = () => controller.abort();
    if (options.signal) {
      if (options.signal.aborted) controller.abort();
      else options.signal.addEventListener('abort', abort, {once: true});
    }
    pending.add(controller);
    const timeoutMs = target.pathname === '/__keymgr/api/keys/batch' ? 9 * 60 * 1000 : 30000;
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(target.pathname + target.search, {...options,
        headers, credentials: 'omit', cache: 'no-store', redirect: 'error', signal: controller.signal});
      if (readToken() !== token) {
        lock('主站登录状态已改变，请重新验证。');
        throw new Error('主站登录状态已改变。');
      }
      if (response.status === 401 ||
          (response.status === 403 && response.headers.get('X-Keymgr-Auth-Required') === '1')) {
        lock('主站管理员登录已失效或权限不足。请回主站登录后重新验证。');
        throw new Error('需要有效的主站管理员登录。');
      }
      return response;
    } finally {
      clearTimeout(timeout); pending.delete(controller);
      if (options.signal) options.signal.removeEventListener('abort', abort);
    }
  };

  async function bootstrap() {
    lock('正在验证主站管理员登录状态…');
    const ownGeneration = generation;
    if (location.origin !== mainOrigin || !/^https:\/\//.test(adminOrigin)) {
      lock('页面来源无效。'); return;
    }
    if (!readToken()) { lock('请先在主站以管理员身份登录。'); return; }
    const startingToken = readToken();
    try {
      const response = await window.keymgrFetch('/__keymgr/api/panel');
      if (!response.ok) throw new Error('暂时无法加载管理页面，请稍后重试。');
      const html = await response.text();
      if (generation !== ownGeneration || readToken() !== startingToken) return;
      // This HTML comes only from our authenticated, same-origin static panel route.
      panel.innerHTML = html; panel.hidden = false; gate.hidden = true;
      if (typeof window.startKeyManager !== 'function') throw new Error('管理页面脚本未加载。');
      await window.startKeyManager();
    } catch (error) {
      if (generation === ownGeneration) lock(error.name === 'AbortError' ? '请求超时，请重新验证。' : error.message);
    }
  }

  document.getElementById('keymgr-auth-retry').addEventListener('click', bootstrap);
  window.addEventListener('storage', event => {
    if (event.key === 'auth_token' || event.key === null) {
      if (!readToken()) lock('主站已退出登录。');
      else bootstrap();
    }
  });
  window.addEventListener('pageshow', bootstrap);
  window.addEventListener('pagehide', () => lock('页面已离开。'));
  // Storage events are delayed in some background tabs; verify on re-entry too.
  window.addEventListener('focus', () => { if (!readToken()) lock('主站已退出登录。'); });
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && !readToken()) lock('主站已退出登录。');
  });
})();
