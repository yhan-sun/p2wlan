(() => {
  'use strict';

  const PAGE_SIZE = 50;
  const titles = {
    overview: '概览',
    devices: '设备',
    networks: '网络',
    rooms: '房间',
    operations: '运行状态',
  };
  const state = {
    token: sessionStorage.getItem('p2wlan-admin-token') || '',
    view: 'overview',
    overview: null,
    runtime: null,
    devices: { offset: 0, total: 0, query: '', status: 'all' },
    networks: { offset: 0, total: 0 },
    rooms: { offset: 0, total: 0 },
  };

  const byId = (id) => document.getElementById(id);
  const loginView = byId('loginView');
  const appView = byId('appView');
  const notice = byId('globalNotice');

  function text(value) {
    return value === null || value === undefined || value === '' ? '—' : String(value);
  }

  function td(value, className = '') {
    const cell = document.createElement('td');
    cell.textContent = text(value);
    if (className) cell.className = className;
    return cell;
  }

  function primaryCell(primary, secondary) {
    const cell = document.createElement('td');
    const main = document.createElement('span');
    main.className = 'primary-cell';
    main.textContent = text(primary);
    cell.appendChild(main);
    if (secondary) {
      const sub = document.createElement('span');
      sub.className = 'secondary-line';
      sub.textContent = secondary;
      cell.appendChild(sub);
    }
    return cell;
  }

  function stateCell(online) {
    const cell = document.createElement('td');
    const value = document.createElement('span');
    value.className = `state ${online ? 'state-online' : ''}`;
    value.textContent = online ? '在线' : '离线';
    cell.appendChild(value);
    return cell;
  }

  function tagCell(label, className = '') {
    const cell = document.createElement('td');
    const tag = document.createElement('span');
    tag.className = `tag ${className}`.trim();
    tag.textContent = label;
    cell.appendChild(tag);
    return cell;
  }

  function emptyRow(body, columns, label = '暂无数据') {
    body.replaceChildren();
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = columns;
    cell.className = 'empty-cell';
    cell.textContent = label;
    row.appendChild(cell);
    body.appendChild(row);
  }

  function formatDate(unix) {
    if (!unix) return '—';
    return new Intl.DateTimeFormat('zh-CN', {
      month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false,
    }).format(new Date(unix * 1000));
  }

  function formatFullDate(unix) {
    if (!unix) return '—';
    return new Intl.DateTimeFormat('zh-CN', {
      year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
    }).format(new Date(unix * 1000));
  }

  function formatAgo(unix) {
    if (!unix) return '从未';
    const seconds = Math.max(0, Math.floor(Date.now() / 1000) - unix);
    if (seconds < 60) return '刚刚';
    if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`;
    if (seconds < 86400 * 30) return `${Math.floor(seconds / 86400)} 天前`;
    return formatDate(unix);
  }

  function formatDuration(seconds) {
    seconds = Math.max(0, Number(seconds) || 0);
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    if (days) return `${days} 天 ${hours} 小时`;
    if (hours) return `${hours} 小时 ${minutes} 分钟`;
    return `${minutes} 分钟`;
  }

  function shortCommit(commit) {
    if (!commit || commit === 'unknown') return 'unknown';
    return commit.slice(0, 10);
  }

  function natLabel(value) {
    const raw = String(value || '').trim();
    if (!raw || raw.toLowerCase() === 'unknown') return 'Unknown';
    const match = raw.match(/(?:^|;)m=([^;]+)/i);
    if (match) return match[1].replaceAll('_', ' ');
    return raw.length <= 22 ? raw : 'Observed';
  }

  function showNotice(message) {
    notice.textContent = message;
    notice.hidden = !message;
  }

  function setUpdatedNow() {
    byId('lastUpdated').textContent = `更新于 ${new Intl.DateTimeFormat('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(new Date())}`;
  }

  async function api(path) {
    const response = await fetch(path, {
      headers: { Authorization: `Bearer ${state.token}`, Accept: 'application/json' },
      cache: 'no-store',
    });
    if (response.status === 401) {
      clearSession();
      showLogin('管理员令牌无效或已变更。');
      throw new Error('unauthorized');
    }
    if (!response.ok) {
      let message = `请求失败（HTTP ${response.status}）`;
      try {
        const payload = await response.json();
        if (payload.error) message = payload.error;
      } catch (_) {
        // Keep the status-based message when the server returned no JSON.
      }
      throw new Error(message);
    }
    return response.json();
  }

  function showLogin(message = '') {
    appView.hidden = true;
    loginView.hidden = false;
    byId('loginError').textContent = message;
    byId('adminToken').value = '';
    byId('adminToken').focus();
  }

  function showApp() {
    loginView.hidden = true;
    appView.hidden = false;
  }

  function clearSession() {
    state.token = '';
    sessionStorage.removeItem('p2wlan-admin-token');
  }

  function renderRecentDevices(items) {
    const body = byId('recentDevicesBody');
    if (!items || items.length === 0) {
      emptyRow(body, 6);
      return;
    }
    body.replaceChildren();
    items.forEach((item) => {
      const row = document.createElement('tr');
      row.append(
        primaryCell(item.device_name, item.platform || '未知平台'),
        td(item.username),
        td(item.network_name),
        td(item.virtual_ip, 'mono'),
        stateCell(item.online),
        td(formatAgo(item.last_seen)),
      );
      body.appendChild(row);
    });
  }

  function renderOverview(data) {
    state.overview = data;
    byId('metricOnline').textContent = data.online_devices;
    byId('metricDevices').textContent = data.devices;
    byId('metricNetworks').textContent = data.networks;
    byId('metricRooms').textContent = data.rooms;
    byId('metricUsers').textContent = data.users;
    byId('metricTunnels').textContent = data.active_tunnels;
    byId('metricSignals').textContent = data.pending_signals;
    byId('metricOnlineRatio').textContent = data.devices ? `${Math.round(data.online_devices / data.devices * 100)}% 在线` : '暂无设备';
    byId('opsSignals').textContent = data.pending_signals;
    byId('opsTunnels').textContent = data.active_tunnels;
    byId('opsOnline').textContent = data.online_devices;
    renderRecentDevices(data.recent_devices);
  }

  function renderRuntime(data) {
    state.runtime = data;
    const commit = shortCommit(data.build_commit);
    byId('runtimeVersion').textContent = data.build_version;
    byId('runtimeCommit').textContent = commit;
    byId('runtimeUptime').textContent = formatDuration(data.uptime_seconds);
    byId('opsVersion').textContent = data.build_version;
    byId('opsCommit').textContent = data.build_commit;
    byId('opsStartedAt').textContent = formatFullDate(data.started_at);
    byId('opsUptime').textContent = formatDuration(data.uptime_seconds);
  }

  async function loadOverview() {
    const [overview, runtime] = await Promise.all([
      api('/admin/api/v1/overview'),
      api('/admin/api/v1/runtime'),
    ]);
    renderOverview(overview);
    renderRuntime(runtime);
    setUpdatedNow();
  }

  function renderDevicePage(page) {
    state.devices.total = page.total;
    const body = byId('devicesBody');
    if (!page.items.length) {
      emptyRow(body, 8, '没有符合条件的设备');
    } else {
      body.replaceChildren();
      page.items.forEach((item) => {
        const row = document.createElement('tr');
        row.append(
          primaryCell(item.device_name, [item.platform, item.app_version].filter(Boolean).join(' · ')),
          td(item.username),
          td(item.network_name),
          td(item.virtual_ip, 'mono'),
          td(natLabel(item.nat_type)),
          td(item.relay_rtt_ms === undefined ? '—' : `${item.relay_rtt_ms} ms`),
          stateCell(item.online),
          td(formatAgo(item.last_seen)),
        );
        body.appendChild(row);
      });
    }
    const start = page.total === 0 ? 0 : page.offset + 1;
    const end = Math.min(page.total, page.offset + page.items.length);
    byId('deviceCountLabel').textContent = `共 ${page.total} 台设备`;
    byId('devicePageLabel').textContent = `${start}–${end} / ${page.total}`;
    byId('devicePrev').disabled = page.offset === 0;
    byId('deviceNext').disabled = page.offset + page.items.length >= page.total;
  }

  async function loadDevices(reset = false) {
    if (reset) state.devices.offset = 0;
    const params = new URLSearchParams({
      limit: String(PAGE_SIZE),
      offset: String(state.devices.offset),
      q: state.devices.query,
      status: state.devices.status,
    });
    renderDevicePage(await api(`/admin/api/v1/devices?${params}`));
    setUpdatedNow();
  }

  function renderNetworkPage(page) {
    state.networks.total = page.total;
    const body = byId('networksBody');
    if (!page.items.length) {
      emptyRow(body, 8);
    } else {
      body.replaceChildren();
      page.items.forEach((item) => {
        const row = document.createElement('tr');
        row.append(
          primaryCell(item.name, item.id),
          td(item.cidr, 'mono'),
          td(item.owner_username),
          td(item.member_count),
          td(item.device_count),
          td(item.online_devices),
          tagCell(item.is_room ? '房间网络' : '个人网络', item.is_room ? 'tag-room' : ''),
          td(formatDate(item.created_at)),
        );
        body.appendChild(row);
      });
    }
    const start = page.total === 0 ? 0 : page.offset + 1;
    const end = Math.min(page.total, page.offset + page.items.length);
    byId('networkCountLabel').textContent = `共 ${page.total} 个网络`;
    byId('networkPageLabel').textContent = `${start}–${end} / ${page.total}`;
    byId('networkPrev').disabled = page.offset === 0;
    byId('networkNext').disabled = page.offset + page.items.length >= page.total;
  }

  async function loadNetworks() {
    const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(state.networks.offset) });
    renderNetworkPage(await api(`/admin/api/v1/networks?${params}`));
    setUpdatedNow();
  }

  function renderRoomPage(page) {
    state.rooms.total = page.total;
    const body = byId('roomsBody');
    if (!page.items.length) {
      emptyRow(body, 8);
    } else {
      body.replaceChildren();
      page.items.forEach((item) => {
        const row = document.createElement('tr');
        row.append(
          primaryCell(item.name, item.id),
          td(item.code, 'mono'),
          td(item.cidr, 'mono'),
          td(item.owner_username),
          td(item.member_count),
          td(item.device_count),
          td(item.online_devices),
          tagCell(item.join_locked ? '已锁定' : '可加入', item.join_locked ? 'tag-locked' : ''),
        );
        body.appendChild(row);
      });
    }
    const start = page.total === 0 ? 0 : page.offset + 1;
    const end = Math.min(page.total, page.offset + page.items.length);
    byId('roomCountLabel').textContent = `共 ${page.total} 个房间`;
    byId('roomPageLabel').textContent = `${start}–${end} / ${page.total}`;
    byId('roomPrev').disabled = page.offset === 0;
    byId('roomNext').disabled = page.offset + page.items.length >= page.total;
  }

  async function loadRooms() {
    const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(state.rooms.offset) });
    renderRoomPage(await api(`/admin/api/v1/rooms?${params}`));
    setUpdatedNow();
  }

  async function loadOperations() {
    const [overview, runtime] = await Promise.all([
      api('/admin/api/v1/overview'),
      api('/admin/api/v1/runtime'),
    ]);
    renderOverview(overview);
    renderRuntime(runtime);
    setUpdatedNow();
  }

  async function refreshCurrent() {
    showNotice('');
    byId('refreshButton').disabled = true;
    try {
      if (state.view === 'overview') await loadOverview();
      else if (state.view === 'devices') await loadDevices();
      else if (state.view === 'networks') await loadNetworks();
      else if (state.view === 'rooms') await loadRooms();
      else await loadOperations();
    } catch (error) {
      if (error.message !== 'unauthorized') showNotice(error.message || '加载失败');
    } finally {
      byId('refreshButton').disabled = false;
    }
  }

  async function switchView(view) {
    if (!titles[view]) return;
    state.view = view;
    document.querySelectorAll('.nav-item').forEach((item) => item.classList.toggle('is-active', item.dataset.view === view));
    document.querySelectorAll('.view').forEach((item) => item.classList.toggle('is-visible', item.id === `view-${view}`));
    byId('pageTitle').textContent = titles[view];
    byId('breadcrumbLabel').textContent = titles[view];
    await refreshCurrent();
  }

  let searchTimer = null;
  byId('deviceSearch').addEventListener('input', (event) => {
    state.devices.query = event.target.value.trim();
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => loadDevices(true).catch((error) => showNotice(error.message)), 250);
  });
  byId('deviceStatus').addEventListener('change', (event) => {
    state.devices.status = event.target.value;
    loadDevices(true).catch((error) => showNotice(error.message));
  });

  document.querySelectorAll('.nav-item').forEach((item) => item.addEventListener('click', () => switchView(item.dataset.view)));
  document.querySelectorAll('[data-jump]').forEach((item) => item.addEventListener('click', () => switchView(item.dataset.jump)));
  byId('refreshButton').addEventListener('click', refreshCurrent);
  byId('logoutButton').addEventListener('click', () => {
    clearSession();
    showLogin();
  });

  byId('devicePrev').addEventListener('click', () => { state.devices.offset = Math.max(0, state.devices.offset - PAGE_SIZE); loadDevices().catch((error) => showNotice(error.message || '加载失败')); });
  byId('deviceNext').addEventListener('click', () => { state.devices.offset += PAGE_SIZE; loadDevices().catch((error) => showNotice(error.message || '加载失败')); });
  byId('networkPrev').addEventListener('click', () => { state.networks.offset = Math.max(0, state.networks.offset - PAGE_SIZE); loadNetworks().catch((error) => showNotice(error.message || '加载失败')); });
  byId('networkNext').addEventListener('click', () => { state.networks.offset += PAGE_SIZE; loadNetworks().catch((error) => showNotice(error.message || '加载失败')); });
  byId('roomPrev').addEventListener('click', () => { state.rooms.offset = Math.max(0, state.rooms.offset - PAGE_SIZE); loadRooms().catch((error) => showNotice(error.message || '加载失败')); });
  byId('roomNext').addEventListener('click', () => { state.rooms.offset += PAGE_SIZE; loadRooms().catch((error) => showNotice(error.message || '加载失败')); });

  byId('loginForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    const token = byId('adminToken').value.trim();
    if (token.length < 32) {
      byId('loginError').textContent = '管理员令牌至少需要 32 个字符。';
      return;
    }
    state.token = token;
    byId('loginError').textContent = '';
    try {
      await api('/admin/api/v1/runtime');
      sessionStorage.setItem('p2wlan-admin-token', token);
      showApp();
      await switchView('overview');
    } catch (error) {
      if (error.message !== 'unauthorized') byId('loginError').textContent = error.message || '无法连接到管理接口。';
    }
  });

  async function bootstrap() {
    if (!state.token) {
      showLogin();
      return;
    }
    try {
      await api('/admin/api/v1/runtime');
      showApp();
      await switchView('overview');
    } catch (error) {
      if (error.message !== 'unauthorized') showLogin(error.message || '无法连接到管理接口。');
    }
  }

  bootstrap();
})();
