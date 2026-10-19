(function () {
  'use strict';
  let previousCleanup = null;
  const statusNames = {active: '正常', inactive: '停用', disabled: '停用', expired: '已过期', quota_exhausted: '额度耗尽'};
  const money = value => value == null ? '—' : String(value);
  const statusName = value => statusNames[value] || value || '—';
  const formatTime = value => {
    if (!value) return '永不过期';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '时间无效';
    return new Intl.DateTimeFormat('zh-CN', {timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23'}).format(date);
  };
  const chinaInput = value => {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '' : new Date(date.getTime() + 8 * 3600000).toISOString().slice(0, 16);
  };
  function expiryValue(input, never) {
    if (never.checked) return '';
    if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d$/.test(input.value)) throw new Error('请选择到期时间，或勾选永不过期。');
    const date = new Date(input.value + ':00+08:00');
    if (Number.isNaN(date.getTime()) || chinaInput(date) !== input.value) throw new Error('到期时间无效。');
    return date.toISOString();
  }
  function nonnegative(input, label, integer) {
    const value = Number(input.value);
    if (input.value.trim() === '' || !Number.isFinite(value) || value < 0 || (integer && !Number.isSafeInteger(value))) throw new Error(label + '必须为非负' + (integer ? '整数。' : '数字。'));
    return value;
  }
  function concurrencyValue(input) {
    const value = nonnegative(input, '并发上限', true);
    if (value < 1 || value > 10000) throw new Error('并发上限为 1 到 10000 的整数。');
    return value;
  }
  function uuid() {
    if (crypto.randomUUID) return crypto.randomUUID();
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
    const hex = Array.from(bytes, n => n.toString(16).padStart(2, '0')).join('');
    return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join('-');
  }
  function errorText(error) {
    if (typeof error === 'string') return error;
    return error && (error.message || error.error || error.reason) || '操作失败，请稍后重试。';
  }
  function makeElement(tag, text, className) {
    const element = document.createElement(tag);
    if (text != null) element.textContent = String(text);
    if (className) element.className = className;
    return element;
  }

  window.startKeyManager = function () {
    if (previousCleanup) previousCleanup();
    const panel = document.getElementById('keymgr-management');
    if (!panel) return;
    const get = id => panel.querySelector('#km-' + id);
    const listener = new AbortController();
    const requests = new Set();
    const state = {live: true, groups: [], keys: [], batchItems: [], batches: [], lastBatch: null, page: 1, pages: 1, total: 0, search: '', status: '', listVersion: 0, batchBusy: false, editBusy: false, editKey: null, editAttempts: new Map()};
    const concurrencyEnabled = true;
    get('create-concurrency-field').hidden = !concurrencyEnabled;
    get('edit-concurrency-field').hidden = !concurrencyEnabled;
    function on(element, event, action) { element.addEventListener(event, action, {signal: listener.signal}); }
    function message(id, text, error) {
      if (!state.live) return;
      get(id).textContent = text;
      get(id).classList.toggle('km-error', Boolean(error));
    }
    async function api(path, options) {
      if (!state.live) throw new Error('会话已退出。');
      const controller = new AbortController(); requests.add(controller);
      try {
        const config = Object.assign({}, options || {}, {signal: controller.signal});
        config.headers = Object.assign({'Accept': 'application/json'}, config.headers || {});
        if (config.body != null && typeof config.body !== 'string') {
          config.body = JSON.stringify(config.body);
          config.headers['Content-Type'] = 'application/json';
        }
        const response = await window.keymgrFetch('/__keymgr/api' + path, config);
        const body = await response.json();
        if (!state.live) throw new Error('会话已退出。');
        if (!response.ok || body.error) throw new Error(errorText(body.error || body.message || '请求失败（HTTP ' + response.status + '）。'));
        return Object.prototype.hasOwnProperty.call(body, 'data') ? body.data : body;
      } finally { requests.delete(controller); }
    }
    async function copy(text) {
      if (!text || !state.live) return;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) await navigator.clipboard.writeText(text);
        else {
          const area = makeElement('textarea'); area.value = text; area.setAttribute('aria-label', '待复制内容');
          area.style.position = 'fixed'; area.style.opacity = '0'; panel.append(area); area.select();
          const done = document.execCommand('copy'); area.value = ''; area.remove();
          if (!done) throw new Error('复制不可用');
        }
        message('notice', '已复制。');
      } catch (_) { message('notice', '浏览器未允许复制，请点击显示后手动选择复制。', true); }
    }
    function groupLabel(key) {
      if (key.group && key.group.name) return key.group.name;
      const found = state.groups.find(group => Number(group.id) === Number(key.group_id));
      return found ? found.name : key.group_id ? '#' + key.group_id : '未绑定';
    }
    function secretCell(key, visible) {
      const cell = makeElement('td');
      let shown = visible;
      const raw = String(key || '');
      const masked = raw.length > 14 ? raw.slice(0, 7) + '…' + raw.slice(-4) : '••••••••';
      const content = makeElement('code', shown ? raw : masked, 'km-key-value');
      const toggle = makeElement('button', shown ? '遮盖' : '显示'); toggle.type = 'button';
      toggle.setAttribute('aria-expanded', String(shown));
      on(toggle, 'click', () => { shown = !shown; content.textContent = shown ? raw : masked; toggle.textContent = shown ? '遮盖' : '显示'; toggle.setAttribute('aria-expanded', String(shown)); });
      const copyButton = makeElement('button', '复制'); copyButton.type = 'button';
      on(copyButton, 'click', () => copy(raw)); cell.append(content, toggle, copyButton); return cell;
    }
    function populateGroups() {
      const createSelect = get('create-group'), editSelect = get('edit-group');
      const previous = createSelect.value;
      createSelect.replaceChildren(); editSelect.replaceChildren();
      const placeholder = makeElement('option', state.groups.length ? '请选择分组' : '暂无可用分组，请先在主站配置'); placeholder.value = ''; createSelect.append(placeholder);
      const keep = makeElement('option', '保持当前分组'); keep.value = 'keep'; editSelect.append(keep);
      for (const group of state.groups) {
        for (const select of [createSelect, editSelect]) {
          const option = makeElement('option', '#' + group.id + ' ' + group.name + (group.subscription_type === 'subscription' ? ' [订阅]' : '')); option.value = String(group.id); select.append(option);
        }
      }
      if (state.groups.some(group => String(group.id) === previous)) createSelect.value = previous;
    }
    async function loadGroups() {
      const groups = await api('/groups');
      if (!Array.isArray(groups)) throw new Error('分组返回格式异常。');
      state.groups = groups.filter(group => !group.subscription_type || group.subscription_type === 'standard');
      populateGroups();
    }
    async function loadBatches() {
      const data = await api('/batches');
      if (!Array.isArray(data)) throw new Error('未完成批次返回格式异常。');
      state.batches = data.filter(batch => batch && batch.request && typeof batch.request.request_id === 'string');
      const previous = get('resume-select').value;
      get('resume-select').replaceChildren();
      for (const batch of state.batches) {
        const request = batch.request;
        const label = (request.name_prefix || '批次') + ' / 已就绪 ' + (Number(batch.ready) || 0) + ' / 共 ' + (Number(batch.total) || request.count || 0) + ' / 待处理 ' + (Number(batch.pending) || 0) + (batch.created_at ? ' / ' + formatTime(batch.created_at) : '') + ' / ' + request.request_id.slice(0, 8);
        const option = makeElement('option', label); option.value = request.request_id; get('resume-select').append(option);
      }
      if (state.batches.some(batch => batch.request.request_id === previous)) get('resume-select').value = previous;
      get('resume-section').hidden = state.batches.length === 0;
      get('resume').disabled = state.batchBusy || state.batches.length === 0;
    }
    function showAccount(user) {
      if (!user) return;
      get('account').textContent = '当前管理员：' + (user.email || '—') + ' / 用户 ID ' + (user.id || user.user_id) + '。每个 Key 使用独立承载用户的余额与并发，互不共享。';
    }
    async function loadAccount() {
      if (window.KEYMGR_USER) { showAccount(window.KEYMGR_USER); return; }
      const data = await api('/session'); showAccount(data.user || data);
    }
    function renderKeys() {
      get('key-rows').replaceChildren();
      for (const key of state.keys) {
        const tr = makeElement('tr');
        const identity = makeElement('td'); identity.append(makeElement('span', '#' + key.id), makeElement('span', key.name || '—', 'km-cell-name'), makeElement('span', '承载用户 #' + (key.managed_user_id || key.user_id || '—'), 'km-muted'));
        const quota = makeElement('td', money(key.wallet_balance));
        if (concurrencyEnabled) quota.append(makeElement('div', '并发上限 ' + (Number(key.concurrency_limit) > 0 ? key.concurrency_limit : '—'), 'km-muted'));
        tr.append(identity, makeElement('td', groupLabel(key)), makeElement('td', statusName(key.status)), quota, makeElement('td', formatTime(key.expires_at)), secretCell(key.key, false));
        const actions = makeElement('td'); const button = makeElement('button', '修改'); button.type = 'button'; on(button, 'click', () => editKey(key)); actions.append(button); tr.append(actions); get('key-rows').append(tr);
      }
      if (!state.keys.length) { const row = makeElement('tr'); const cell = makeElement('td', '没有符合条件的 Key。'); cell.colSpan = 7; row.append(cell); get('key-rows').append(row); }
      get('page').textContent = '第 ' + state.page + ' / ' + state.pages + ' 页，共 ' + state.total + ' 项';
      get('prev').disabled = state.page <= 1; get('next').disabled = state.page >= state.pages;
    }
    async function loadKeys() {
      const version = ++state.listVersion;
      message('list-message', '读取中…'); get('prev').disabled = true; get('next').disabled = true;
      try {
        const params = {page: state.page, page_size: 25, status: state.status};
        let data;
        if (state.search) data = await api('/keys/search', {method: 'POST', body: Object.assign(params, {search: state.search})});
        else data = await api('/keys?' + new URLSearchParams(params));
        if (version !== state.listVersion || !state.live) return;
        state.keys = Array.isArray(data.items) ? data.items : [];
        state.total = Number(data.total) || 0; state.pages = Math.max(1, Number(data.pages) || Math.ceil(state.total / 25));
        state.page = Number(data.page) || state.page;
        renderKeys(); message('list-message', '查询完成。已有 Key 默认遮盖。');
      } catch (error) {
        if (version !== state.listVersion || !state.live) return;
        state.keys = []; get('key-rows').replaceChildren(); message('list-message', errorText(error), true);
      }
    }
    function successfulBatchKeys() { return state.batchItems.filter(item => !item.error && item.key && item.key.key).map(item => item.key); }
    function renderBatch(data) {
      state.batchItems = Array.isArray(data.items) ? data.items : [];
      const table = makeElement('table', null, 'km-table');
      const head = makeElement('thead'); const hr = makeElement('tr');
      for (const title of ['序号', '结果 / ID', '名称', 'Key / 错误']) hr.append(makeElement('th', title));
      head.append(hr); const body = makeElement('tbody');
      for (const item of state.batchItems) {
        const row = makeElement('tr'); row.append(makeElement('td', item.index == null ? '—' : item.index));
        if (item.error || !item.key) {
          row.append(makeElement('td', '失败', 'km-error'), makeElement('td', '—'), makeElement('td', errorText(item.error), 'km-error'));
        } else {
          row.append(makeElement('td', '成功 / #' + item.key.id), makeElement('td', item.key.name || '—'), secretCell(item.key.key, true));
        }
        body.append(row);
      }
      table.append(head, body); get('batch-results').replaceChildren(table); get('batch-results').hidden = false;
      const succeeded = Number.isFinite(Number(data.created)) ? Number(data.created) : successfulBatchKeys().length;
      const failed = Number.isFinite(Number(data.failed)) ? Number(data.failed) : state.batchItems.length - succeeded;
      message('batch-message', '本批结果：成功 ' + succeeded + ' 项，失败 ' + failed + ' 项。成功项的完整 Key 显示如下，请按需复制或下载。' + (failed ? ' 已成功的 Key 已保留，请查看失败原因。' : ''), failed > 0);
      get('copy-batch').disabled = successfulBatchKeys().length === 0; get('download-batch').disabled = successfulBatchKeys().length === 0;
    }
    async function runBatch() {
      if (state.batchBusy || !state.lastBatch) return;
      state.batchBusy = true; get('create-submit').disabled = true; get('retry').disabled = true; get('resume').disabled = true;
      get('batch-actions').hidden = false; get('retry-note').hidden = false;
      message('batch-message', '批量处理中；主站请求频率限制可能需要数分钟，请勿新建相同批次。请求编号 ' + state.lastBatch.request_id + '。');
      try {
        const data = await api('/keys/batch', {method: 'POST', body: state.lastBatch});
        renderBatch(data); await loadKeys();
      } catch (error) {
        message('batch-message', errorText(error) + ' 若响应中断，不能据此认定全部失败；请点击“重试同一批请求”复用原请求编号。', true);
      } finally {
        state.batchBusy = false;
        if (state.live) {
          get('create-submit').disabled = false; get('retry').disabled = false;
          try { await loadBatches(); }
          catch (error) { message('notice', '未完成批次列表刷新失败：' + errorText(error), true); }
        }
      }
    }
    function editKey(key) {
      if (state.editBusy) return;
      state.editKey = key;
      get('edit-identity').textContent = '#' + key.id + ' / ' + (key.name || '—') + ' / 承载用户 #' + (key.managed_user_id || key.user_id || '—') + ' / 当前余额 ¥ ' + money(key.wallet_balance) + ' / 当前分组：' + groupLabel(key) + ' / 当前状态：' + statusName(key.status);
      get('edit-group').value = 'keep'; get('edit-balance-mode').value = 'add'; get('edit-balance-amount').value = '';
      get('edit-never').checked = !key.expires_at; get('edit-expiry').value = key.expires_at ? chinaInput(key.expires_at) : '';
      get('edit-expiry').disabled = get('edit-never').checked;
      get('edit-status').value = ['active', 'inactive'].includes(key.status) ? key.status : 'keep';
      get('edit-concurrency').value = String(key.concurrency_limit || 1);
      get('edit-submit').textContent = '保存修改';
      message('edit-message', '余额金额留空则不变。增加 / 扣减为差额操作，设置为目标余额；不修改原生 Key 总额度。');
      get('edit-section').hidden = false; get('edit-section').scrollIntoView({behavior: 'smooth', block: 'start'}); get('edit-balance-amount').focus({preventScroll: true});
    }
    on(get('create-never'), 'change', () => { get('create-expiry').disabled = get('create-never').checked; });
    on(get('edit-never'), 'change', () => { get('edit-expiry').disabled = get('edit-never').checked; });
    get('create-expiry').disabled = true;
    on(get('create'), 'submit', event => {
      event.preventDefault(); if (state.batchBusy) return;
      try {
        const count = nonnegative(get('count'), '数量', true);
        if (count < 1 || count > 100) throw new Error('每批数量为 1 到 100。');
        const group = Number(get('create-group').value);
        if (!Number.isSafeInteger(group) || group <= 0) throw new Error('请选择可用分组。');
        const prefix = get('prefix').value.trim(); if (!prefix) throw new Error('请填写名称前缀。');
        const payload = {request_id: uuid(), count, name_prefix: prefix, group_id: group, quota: nonnegative(get('create-quota'), '初始余额'), expires_at: expiryValue(get('create-expiry'), get('create-never')), concurrency: concurrencyValue(get('create-concurrency'))};
        if (payload.expires_at && new Date(payload.expires_at).getTime() <= Date.now()) throw new Error('新建 Key 的到期时间须晚于当前时间。');
        state.lastBatch = Object.freeze(payload); state.batchItems = []; get('batch-results').replaceChildren(); get('batch-results').hidden = true;
        get('copy-batch').disabled = true; get('download-batch').disabled = true; runBatch();
      } catch (error) { message('batch-message', errorText(error), true); }
    });
    on(get('retry'), 'click', runBatch);
    on(get('resume'), 'click', () => {
      if (state.batchBusy) return;
      const batch = state.batches.find(item => item.request.request_id === get('resume-select').value);
      if (!batch) return;
      state.lastBatch = Object.freeze(Object.assign({}, batch.request)); state.batchItems = [];
      get('batch-results').replaceChildren(); get('batch-results').hidden = true;
      get('copy-batch').disabled = true; get('download-batch').disabled = true;
      runBatch();
    });
    on(get('copy-batch'), 'click', () => copy(successfulBatchKeys().map(key => key.key).join('\n')));
    on(get('download-batch'), 'click', () => {
      const keys = successfulBatchKeys(); if (!keys.length) return;
      const csvCell = value => '"' + String(value == null ? '' : value).replace(/"/g, '""') + '"';
      const rows = [['ID', '名称', 'API Key', '承载用户 ID', '分组 ID', '余额 ¥', '并发上限', '到期时间 UTC'], ...keys.map(key => [key.id, /^(?:\s*[=+@-]|[\t\r])/.test(key.name || '') ? "'" + key.name : key.name, key.key, key.managed_user_id || key.user_id, key.group_id, key.wallet_balance, key.concurrency_limit, key.expires_at || '永不过期'])];
      const blob = new Blob(['\ufeff' + rows.map(row => row.map(csvCell).join(',')).join('\r\n')], {type: 'text/csv;charset=utf-8'});
      const url = URL.createObjectURL(blob), link = makeElement('a'); link.href = url; link.download = 'api-keys-' + (state.lastBatch ? state.lastBatch.request_id : 'batch') + '.csv'; panel.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
      message('notice', '已生成本批 CSV，请妥善保存其中的完整 Key。');
    });
    on(get('clear-batch'), 'click', () => {
      if (state.batchBusy) { message('batch-message', '本批请求仍在进行，请等待完成后清空。', true); return; }
      state.batchItems = []; state.lastBatch = null; get('batch-results').replaceChildren(); get('batch-results').hidden = true; get('batch-actions').hidden = true; get('retry-note').hidden = true; message('batch-message', '已清空本批结果。');
    });
    on(get('search'), 'submit', event => { event.preventDefault(); state.search = get('search-input').value.trim(); state.status = get('status').value; state.page = 1; loadKeys(); });
    on(get('clear-search'), 'click', () => { get('search-input').value = ''; get('status').value = ''; state.search = ''; state.status = ''; state.page = 1; loadKeys(); });
    on(get('prev'), 'click', () => { if (state.page > 1) { state.page--; loadKeys(); } });
    on(get('next'), 'click', () => { if (state.page < state.pages) { state.page++; loadKeys(); } });
    on(get('edit-cancel'), 'click', () => { if (!state.editBusy) { state.editKey = null; get('edit-section').hidden = true; get('edit').reset(); } });
    on(get('edit'), 'submit', async event => {
      event.preventDefault(); if (state.editBusy || !state.editKey) return;
      try {
        const payload = {concurrency: concurrencyValue(get('edit-concurrency'))};
        if (get('edit-balance-amount').value.trim() !== '') payload.balance_action = {mode: get('edit-balance-mode').value, amount: nonnegative(get('edit-balance-amount'), '余额变更金额')};
        const expiryChanged = get('edit-never').checked !== !state.editKey.expires_at || (!get('edit-never').checked && get('edit-expiry').value !== chinaInput(state.editKey.expires_at));
        if (expiryChanged) payload.expires_at = expiryValue(get('edit-expiry'), get('edit-never'));
        if (get('edit-group').value !== 'keep') payload.group_id = Number(get('edit-group').value);
        if (get('edit-status').value !== 'keep') payload.status = get('edit-status').value;
        const keyID = Number(state.editKey.id), intent = JSON.stringify(payload);
        let attempt = state.editAttempts.get(keyID);
        if (!attempt || attempt.intent !== intent) {
          attempt = {intent, payload: Object.freeze(Object.assign({request_id: uuid()}, payload))};
          state.editAttempts.set(keyID, attempt);
        }
        state.editBusy = true;
        for (const control of get('edit').elements) control.disabled = true;
        message('edit-message', '保存中…');
        const updated = await api('/keys/' + keyID, {method: 'PUT', body: attempt.payload});
        state.editAttempts.delete(keyID);
        state.editKey = updated && updated.id ? updated : state.editKey;
        get('edit-balance-amount').value = '';
        get('edit-submit').textContent = '保存修改';
        message('edit-message', '已保存，余额变更金额已清空，避免再次点击时重复加减。'); await loadKeys();
      } catch (error) {
        message('edit-message', errorText(error) + ' 若响应中断，请保留原参数再次保存，将复用同一请求编号；修改参数则按新操作处理。', true);
        if (state.live) get('edit-submit').textContent = '重试 / 保存修改';
      }
      finally {
        state.editBusy = false;
        if (state.live) {
          for (const control of get('edit').elements) control.disabled = false;
          get('edit-expiry').disabled = get('edit-never').checked;
        }
      }
    });
    async function refresh() {
      get('refresh').disabled = true; message('notice', '刷新中…');
      const results = await Promise.allSettled([loadAccount(), loadGroups(), loadKeys(), loadBatches()]);
      if (!state.live) return;
      get('refresh').disabled = false;
      const failures = results.filter(result => result.status === 'rejected');
      message('notice', failures.length ? failures.map(result => errorText(result.reason)).join('\n') : '数据已刷新。', failures.length > 0);
    }
    on(get('refresh'), 'click', refresh);
    function cleanup() {
      if (!state.live) return;
      state.live = false; listener.abort(); requests.forEach(controller => controller.abort()); requests.clear();
      state.keys = []; state.groups = []; state.batchItems = []; state.batches = []; state.lastBatch = null; state.editKey = null; state.editAttempts.clear(); state.search = '';
      get('key-rows').replaceChildren(); get('batch-results').replaceChildren(); get('batch-results').hidden = true; get('edit-section').hidden = true;
      get('search-input').value = ''; get('create').reset(); get('edit').reset(); get('batch-message').textContent = ''; get('edit-identity').textContent = ''; get('account').textContent = ''; get('notice').textContent = '';
      get('resume-select').replaceChildren(); get('resume-section').hidden = true;
    }
    window.addEventListener('keymgr:logout', cleanup, {signal: listener.signal});
    previousCleanup = cleanup;
    refresh();
  };
})();
