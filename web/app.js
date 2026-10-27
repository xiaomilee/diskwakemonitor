/* 硬盘唤醒监控 —— 面板逻辑
   仅用原生 DOM API，不引入框架；所有样式通过 CSSOM 设置以满足严格 CSP。 */
(function () {
  'use strict';

  var state = {
    hours: 24,
    bucket: 300,
    devices: [],
    summary: null,
    health: null,
    timeline: null,
    wakes: [],
    openRows: new Set(),
    live: false,
    loading: false
  };

  var POLL_MS = 20000;
  var stream = null;
  var pollTimer = null;

  function $(sel) { return document.querySelector(sel); }

  /* ---------------------------------------------------------------- 格式化 */
  function pad(n) { return n < 10 ? '0' + n : String(n); }

  function fmtTime(ts) {
    if (!ts) return '-';
    var d = new Date(ts * 1000);
    return pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' +
           pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }

  function fmtClock(ts) {
    var d = new Date(ts * 1000);
    return pad(d.getHours()) + ':' + pad(d.getMinutes());
  }

  function fmtIdle(sec) {
    if (sec === null || sec === undefined) return '-';
    sec = Number(sec);
    if (sec < 60) return Math.round(sec) + ' 秒';
    if (sec < 3600) return Math.round(sec / 60) + ' 分钟';
    if (sec < 86400) return (sec / 3600).toFixed(1) + ' 小时';
    return (sec / 86400).toFixed(1) + ' 天';
  }

  function fmtBytes(n) {
    n = Number(n || 0);
    var units = ['B', 'K', 'M', 'G', 'T', 'P'];
    var i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n.toFixed(0) : n.toFixed(1)) + units[i];
  }

  var CONF = {
    smart: { label: 'SMART 确认', cls: 'smart' },
    state: { label: '电源态', cls: 'state' },
    inferred: { label: '推断', cls: 'inferred' }
  };

  function confMeta(c) { return CONF[c] || { label: c || '未知', cls: 'none' }; }

  function stateMeta(s) {
    if (s === 'standby') return { label: '休眠', cls: 'sleep' };
    if (s === 'active') return { label: '活跃', cls: 'active' };
    return { label: '未知', cls: 'unknown' };
  }

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  /* ---------------------------------------------------------------- 请求 */
  function fetchJSON(path) {
    return fetch(path, { headers: { Accept: 'application/json' }, cache: 'no-store' })
      .then(function (res) {
        return res.json().then(function (body) {
          if (!res.ok) {
            var msg = (body && body.error && body.error.message) || ('HTTP ' + res.status);
            var err = new Error(msg);
            err.code = body && body.error ? body.error.code : '';
            throw err;
          }
          return body;
        });
      });
  }

  function refresh() {
    if (state.loading) return;
    state.loading = true;
    var btn = $('#refreshBtn');
    btn.classList.add('spin');

    var q = 'hours=' + state.hours;
    Promise.all([
      fetchJSON('/api/health').catch(function () { return null; }),
      fetchJSON('/api/devices?' + q).catch(function () { return { items: [] }; }),
      fetchJSON('/api/summary?' + q).catch(function () { return null; }),
      fetchJSON('/api/wakes?' + q + '&limit=120').catch(function () { return { items: [] }; }),
      fetchJSON('/api/offenders?' + q + '&limit=24').catch(function () { return { items: [] }; }),
      fetchJSON('/api/timeline?' + q + '&bucket=' + state.bucket).catch(function () { return null; })
    ]).then(function (r) {
      state.health = r[0];
      state.devices = (r[1] && r[1].items) || [];
      state.summary = r[2];
      state.wakes = (r[3] && r[3].items) || [];
      state.offenders = (r[4] && r[4].items) || [];
      state.timeline = r[5];
      renderAll();
    }).catch(function (err) {
      showFatal(err.message || '加载失败');
    }).then(function () {
      state.loading = false;
      btn.classList.remove('spin');
    });
  }

  function showFatal(message) {
    var grid = $('#diskGrid');
    grid.textContent = '';
    var box = el('div', 'empty');
    var strong = el('strong', null, '无法读取数据');
    box.appendChild(strong);
    box.appendChild(document.createTextNode(message));
    grid.appendChild(box);
  }

  /* ---------------------------------------------------------------- 渲染 */
  function renderAll() {
    renderStats();
    renderDevices();
    renderTimeline();
    renderWakes();
    renderOffenders();
    renderVersion();
  }

  // 版本号来自 /api/health（后端唯一来源 dwm/__init__.py），前端不硬编码
  function renderVersion() {
    var chip = $('#appVersion');
    if (!chip) return;
    var version = state.health && state.health.version;
    if (!version) {
      chip.hidden = true;
      return;
    }
    chip.textContent = 'v' + version;
    chip.title = '服务端版本 v' + version;
    chip.hidden = false;
  }

  function renderStats() {
    var host = $('#stats');
    host.textContent = '';
    var s = state.summary || {};
    var monitored = state.devices.filter(function (d) { return d.monitored; });
    var collector = (state.health && state.health.collector) || null;
    var source = collector ? collector.source : (state.health && state.health.live ? '采集中' : '只读');
    var io = collector && collector.io_stats;
    var sourceValue = source || '-';
    var sourceCls = '';
    var sourceTitle = '采集进程使用的事件源';
    if (io) {
      sourceValue = sourceValue + ' · ' + io.seen + ' 事件';
      if (io.seen === 0) {
        sourceCls = 'warn';
        sourceTitle = '事件源启动后没有产出任何事件——归因会全部为空。' +
          '运行 dwmctl probe 查看 fanotify 是否可用';
      } else if (io.no_dev > 0 && io.no_dev >= io.kept) {
        sourceCls = 'warn';
        sourceTitle = '有 ' + io.no_dev + ' 个事件无法归属到被监控盘（已丢弃 ' +
          io.no_dev + ' / ' + io.seen + '）。多半是挂载映射问题，运行 dwmctl probe 查看挂载点';
      } else {
        sourceTitle = '已接收 ' + io.seen + ' 个事件，归到被监控盘 ' + io.kept +
          ' 个，无法归属 ' + io.no_dev + ' 个';
      }
    }

    var items = [
      { label: '唤醒次数 · ' + rangeLabel(), value: s.wake_total || 0, unit: '次', cls: 'wake' },
      { label: '未归因', value: s.unattributed || 0, unit: '次',
        cls: (s.unattributed || 0) > 0 ? 'warn' : '' },
      { label: '监控磁盘', value: monitored.length, unit: '块', cls: 'accent' },
      { label: '数据源', value: sourceValue, small: true, cls: sourceCls, title: sourceTitle }
    ];

    items.forEach(function (item) {
      var box = el('div', 'stat ' + (item.cls || ''));
      box.appendChild(el('div', 'stat-label', item.label));
      var val = el('div', 'stat-value', item.value);
      if (item.unit) {
        var small = el('small', null, item.unit);
        val.appendChild(small);
      }
      if (item.small) val.classList.add('mono');
      if (item.title) { box.title = item.title; val.title = item.title; }
      box.appendChild(val);
      host.appendChild(box);
    });
  }

  function rangeLabel() {
    if (state.hours === 1) return '1 小时';
    if (state.hours === 6) return '6 小时';
    if (state.hours === 24) return '24 小时';
    return '7 天';
  }

  function renderDevices() {
    var grid = $('#diskGrid');
    grid.textContent = '';

    if (!state.devices.length) {
      var box = el('div', 'empty');
      box.appendChild(el('strong', null, '还没有识别到磁盘'));
      var line = el('div', null, '先运行自检确认环境：');
      box.appendChild(line);
      var code = el('code', null, 'dwmctl probe');
      var wrap = el('div');
      wrap.appendChild(code);
      box.appendChild(wrap);
      grid.appendChild(box);
      $('#disksHint').textContent = '';
      return;
    }

    var monitored = state.devices.filter(function (d) { return d.monitored; });
    var skipped = state.devices.length - monitored.length;
    $('#disksHint').textContent = skipped > 0
      ? monitored.length + ' 块监控中 · ' + skipped + ' 块跳过'
      : monitored.length + ' 块监控中';

    state.devices.forEach(function (dev) {
      if (!dev.monitored) return;
      var card = el('div', 'disk-card');

      var top = el('div', 'disk-top');
      top.appendChild(el('span', 'disk-name', dev.name));
      var topRight = el('span', 'disk-top-right');
      var st = stateMeta(dev.state);
      var pill = el('span', 'state ' + st.cls);
      pill.appendChild(el('i'));
      pill.appendChild(document.createTextNode(st.label));
      topRight.appendChild(pill);

      var clearBtn = el('button', 'disk-clear');
      clearBtn.type = 'button';
      clearBtn.textContent = '清除';
      clearBtn.title = '清除 ' + dev.name + ' 的唤醒记录';
      clearBtn.setAttribute('aria-label', '清除 ' + dev.name + ' 的唤醒记录');
      clearBtn.addEventListener('click', function (event) {
        event.stopPropagation();
        clearDev(dev.name, dev.wake_count || 0);
      });
      topRight.appendChild(clearBtn);
      top.appendChild(topRight);
      card.appendChild(top);

      card.appendChild(el('div', 'disk-model', dev.model || dev.name));

      var meta = el('div', 'disk-meta');
      meta.appendChild(el('span', 'chip', dev.transport));
      meta.appendChild(el('span', 'chip', fmtBytes(dev.size_bytes)));
      if (dev.mounts && dev.mounts.length) {
        meta.appendChild(el('span', 'chip', dev.mounts.join(' ')));
      }
      if (dev.removable) meta.appendChild(el('span', 'chip', '可移动'));
      card.appendChild(meta);

      var foot = el('div', 'disk-foot');
      var left = el('span');
      left.appendChild(document.createTextNode('唤醒 '));
      left.appendChild(el('strong', null, dev.wake_count || 0));
      left.appendChild(document.createTextNode(' 次'));
      foot.appendChild(left);

      var right = el('span');
      if (dev.last_wake) {
        right.textContent = fmtTime(dev.last_wake.ts);
      } else if (dev.state === 'standby' && dev.idle_seconds) {
        right.textContent = '已静 ' + fmtIdle(dev.idle_seconds);
      } else {
        right.textContent = '无记录';
      }
      foot.appendChild(right);
      card.appendChild(foot);

      grid.appendChild(card);
    });

    if (!monitored.length) {
      var none = el('div', 'empty');
      none.appendChild(el('strong', null, '没有磁盘纳入监控'));
      none.appendChild(document.createTextNode('用 DWM_MONITOR_DEVICES=sdb 显式指定要监控的盘'));
      grid.appendChild(none);
    }
  }

  function renderTimeline() {
    var host = $('#timeline');
    host.textContent = '';
    var data = state.timeline;

    if (!data) {
      host.appendChild(el('div', 'empty', '暂无数据'));
      return;
    }

    var start = data.start;
    var end = data.end;
    var span = Math.max(1, end - start);
    var monitored = state.devices.filter(function (d) { return d.monitored; });
    if (!monitored.length) {
      host.appendChild(el('div', 'empty', '没有可绘制的磁盘'));
      return;
    }

    monitored.forEach(function (dev) {
      var series = (data.series && data.series[dev.name]) || [];
      var wakes = (data.wakes && data.wakes[dev.name]) || [];

      var row = el('div', 'tl-row');
      row.appendChild(el('div', 'tl-label', dev.name));
      var track = el('div', 'tl-track');

      var maxHits = 1;
      series.forEach(function (b) { if (b.hits > maxHits) maxHits = b.hits; });

      series.forEach(function (bucket) {
        var pct = ((bucket.ts - start) / span) * 100;
        if (pct < 0 || pct > 100) return;
        var tick = el('div', 'tl-tick');
        tick.style.left = pct.toFixed(3) + '%';
        tick.style.opacity = (0.15 + 0.85 * (bucket.hits / maxHits)).toFixed(2);
        track.appendChild(tick);
      });

      wakes.forEach(function (wake) {
        var pct = ((wake.ts - start) / span) * 100;
        if (pct < 0 || pct > 100) return;
        var mark = el('div', 'tl-wake');
        mark.style.left = pct.toFixed(3) + '%';
        mark.title = fmtTime(wake.ts) + ' 唤醒 · 嫌疑 ' + wake.suspect_count + ' 个 · ' +
                     confMeta(wake.confidence).label;
        track.appendChild(mark);
      });

      row.appendChild(track);
      host.appendChild(row);
    });

    // 时间轴
    var axis = el('div', 'tl-axis');
    axis.appendChild(el('div'));
    var axisTrack = el('div', 'tl-axis-track');
    var ticks = 5;
    for (var i = 0; i <= ticks; i++) {
      var ratio = i / ticks;
      var label = el('span', null, fmtClock(start + span * ratio));
      label.style.left = (ratio * 100).toFixed(2) + '%';
      if (i === 0) { label.style.transform = 'none'; }
      if (i === ticks) { label.style.transform = 'translateX(-100%)'; }
      axisTrack.appendChild(label);
    }
    axis.appendChild(axisTrack);
    host.appendChild(axis);
  }

  function renderWakes() {
    var body = $('#wakeBody');
    body.textContent = '';
    var emptyBox = $('#wakeEmpty');

    if (!state.wakes.length) {
      emptyBox.hidden = false;
      emptyBox.textContent = '';
      emptyBox.appendChild(el('strong', null, '这段时间没有捕获到唤醒'));
      var collector = (state.health && state.health.collector) || null;
      var io = collector && collector.io_stats;
      var hint;
      if (!collector || collector.source === 'none') {
        hint = '事件源未就绪：请以 root 运行，或执行 dwmctl probe 检查 fanotify 是否可用';
      } else if (io && io.seen === 0) {
        hint = '事件源（' + collector.source + '）启动后没有产出任何访问事件，' +
          '归因会全部为空。执行 dwmctl probe 检查；若 probe 显示正常，' +
          '说明这些唤醒不是文件访问触发的（内核后台任务 / SMART 查询等）';
      } else if (io && io.no_dev > 0 && io.no_dev >= io.kept) {
        hint = '已收到 ' + io.seen + ' 个访问事件，但 ' + io.no_dev +
          ' 个无法归属到被监控盘。多半是挂载映射问题，运行 dwmctl probe 查看各盘挂载点';
      } else {
        hint = '盘没有睡下去就不会有唤醒——先在系统设置里开启硬盘休眠，' +
          '或看「阻止休眠的元凶」排行';
      }
      emptyBox.appendChild(document.createTextNode(hint));
      return;
    }
    emptyBox.hidden = true;

    state.wakes.forEach(function (wake) {
      var tr = el('tr', 'row');
      tr.dataset.id = String(wake.id);

      tr.appendChild(el('td', 'mono col-time', fmtTime(wake.ts)));
      tr.appendChild(el('td', 'mono col-dev', wake.dev));
      tr.appendChild(el('td', 'mono col-idle', fmtIdle(wake.idle_seconds)));

      var topSuspect = wake.suspects && wake.suspects.length ? wake.suspects[0] : null;
      var cell = el('td');
      var proc = el('div', 'proc-cell');
      if (topSuspect) {
        var main = el('div', 'proc-main', topSuspect.comm + '(' + topSuspect.pid + ')');
        proc.appendChild(main);
        var sub = topSuspect.container || topSuspect.cmdline || '';
        if (sub) proc.appendChild(el('div', 'proc-sub', sub));
      } else {
        proc.appendChild(el('div', 'proc-main dim', '未捕获到访问事件'));
      }
      cell.appendChild(proc);
      tr.appendChild(cell);

      var conf = confMeta(wake.confidence);
      var confCell = el('td');
      confCell.appendChild(el('span', 'badge ' + conf.cls,
        wake.suspect_count ? conf.label : '无归因'));
      tr.appendChild(confCell);

      body.appendChild(tr);
      if (state.openRows.has(wake.id)) {
        body.appendChild(buildDetailRow(wake));
        tr.classList.add('is-open');
      }

      tr.addEventListener('click', function () {
        toggleRow(wake.id);
      });
    });
  }

  function buildDetailRow(wake) {
    var tr = el('tr', 'detail');
    var td = el('td');
    td.colSpan = 5;
    var inner = el('div', 'detail-inner');

    if (wake.note) {
      inner.appendChild(el('div', 'detail-note', wake.note));
    }

    if (wake.suspects && wake.suspects.length) {
      wake.suspects.slice(0, 8).forEach(function (s, index) {
        var row = el('div', 'suspect');
        row.appendChild(el('div', 'suspect-rank', '#' + (index + 1)));

        var main = el('div', 'suspect-main');
        var name = el('div', 'suspect-name', s.comm + '(' + s.pid + ')');
        if (s.container) {
          var tag = el('span', 'tag-container', s.container);
          tag.style.marginLeft = '6px';
          name.appendChild(document.createTextNode(' '));
          name.appendChild(tag);
        }
        main.appendChild(name);

        var path = s.sample_path || s.cmdline || '';
        if (path) main.appendChild(el('div', 'suspect-path', path));
        row.appendChild(main);

        row.appendChild(el('div', 'suspect-hits', s.hits + ' 次'));
        inner.appendChild(row);
      });
    } else {
      inner.appendChild(el('div', 'detail-note',
        '归因窗口内没有任何被监控磁盘的访问记录。常见原因：唤醒由内核后台任务（如 btrfs scrub、' +
        'md 阵列校验）、SMART 查询或硬盘盒固件自身触发，也可能是事件源没有拿到 root 权限。'));
    }

    td.appendChild(inner);
    tr.appendChild(td);
    return tr;
  }

  function toggleRow(id) {
    if (state.openRows.has(id)) {
      state.openRows.delete(id);
    } else {
      state.openRows.add(id);
    }
    renderWakes();
  }

  function renderOffenders() {
    var host = $('#offenderList');
    host.textContent = '';

    if (!state.offenders.length) {
      var box = el('div', 'empty');
      box.appendChild(el('strong', null, '还没有访问记录'));
      box.appendChild(document.createTextNode('采集运行一段时间后这里会列出最频繁访问磁盘的进程'));
      host.appendChild(box);
      return;
    }

    var maxHits = 1;
    state.offenders.forEach(function (o) { if (o.hits > maxHits) maxHits = o.hits; });

    state.offenders.forEach(function (item, index) {
      var row = el('div', 'offender');

      var bar = el('div', 'offender-bar');
      bar.style.width = Math.max(2, (item.hits / maxHits) * 100).toFixed(1) + '%';
      row.appendChild(bar);

      row.appendChild(el('div', 'offender-rank', String(index + 1)));

      var main = el('div', 'offender-main');
      main.appendChild(el('div', 'offender-name', item.comm || '(未知进程)'));

      var subParts = [item.dev];
      if (item.container) subParts.push(item.container);
      subParts.push('最近 ' + fmtTime(item.last_ts));
      main.appendChild(el('div', 'offender-sub', subParts.join(' · ')));
      row.appendChild(main);

      var hits = el('div', 'offender-hits', String(item.hits));
      hits.appendChild(el('small', null, '次'));
      row.appendChild(hits);

      host.appendChild(row);
    });
  }

  /* ---------------------------------------------------------------- 清除 */
  function clearDev(dev, wakeCount) {
    var message = '确定清除 ' + dev + ' 的全部唤醒记录' +
      (wakeCount ? '（共 ' + wakeCount + ' 条）' : '') +
      '？\n\n将同时删除该盘的访问明细与电源记录，操作不可撤销。';
    if (!window.confirm(message)) return;
    var body = JSON.stringify({ dev: dev, access: true });
    fetch('/api/clear', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: body
    }).then(function (res) {
      return res.json().then(function (data) {
        if (!res.ok) {
          throw new Error((data && data.error && data.error.message) || ('HTTP ' + res.status));
        }
        return data;
      });
    }).then(function (data) {
      showToast('已清除 ' + dev + '：唤醒 ' + (data.wakes || 0) + ' 条，访问 ' +
        (data.access || 0) + ' 条');
      refresh();
    }).catch(function (err) {
      showToast('清除失败：' + err.message, true);
    });
  }

  function showToast(message, isError) {
    var stack = $('#toasts');
    var box = el('div', 'toast' + (isError ? ' toast-error' : ''));
    box.appendChild(el('div', 'toast-title', message));
    stack.appendChild(box);
    setTimeout(function () {
      box.style.opacity = '0';
      box.style.transition = 'opacity .3s';
      setTimeout(function () { box.remove(); }, 320);
    }, isError ? 8000 : 4000);
  }

  /* ---------------------------------------------------------------- 实时 */
  function setLive(ok) {
    state.live = ok;
    var dot = $('#liveDot');
    var pill = $('#livePill');
    var text = $('#liveText');
    dot.classList.toggle('is-live', ok);
    dot.classList.toggle('is-down', !ok);
    pill.classList.toggle('is-live', ok);
    pill.classList.toggle('is-down', !ok);
    text.textContent = ok ? '实时' : '已断开';
  }

  function connectStream() {
    if (!state.health || !state.health.live) {
      setLive(false);
      $('#liveText').textContent = '只读模式';
      return;
    }
    if (stream) stream.close();
    stream = new EventSource('/api/stream');
    stream.onopen = function () { setLive(true); };
    stream.onerror = function () { setLive(false); };
    stream.onmessage = function (event) {
      var data;
      try { data = JSON.parse(event.data); } catch (e) { return; }
      if (data.type === 'wake') {
        toast(data.wake);
        refresh();
      }
    };
  }

  function toast(wake) {
    var stack = $('#toasts');
    var box = el('div', 'toast');
    var title = el('div', 'toast-title');
    title.appendChild(el('span', null, '检测到 ' + wake.dev + ' 被唤醒'));
    title.appendChild(el('span', null, fmtClock(wake.ts)));
    box.appendChild(title);

    var who = wake.suspects && wake.suspects.length
      ? wake.suspects[0].comm + '(' + wake.suspects[0].pid + ')'
      : '未捕获到触发进程';
    var body = el('div', 'toast-body',
      '空闲 ' + fmtIdle(wake.idle_seconds) + ' · ' + who);
    box.appendChild(body);

    stack.appendChild(box);
    setTimeout(function () {
      box.style.opacity = '0';
      box.style.transition = 'opacity .3s';
      setTimeout(function () { box.remove(); }, 320);
    }, 6000);
  }

  /* ---------------------------------------------------------------- 交互 */
  function bind() {
    var group = $('#rangeGroup');
    group.addEventListener('click', function (event) {
      var btn = event.target.closest('button[data-hours]');
      if (!btn) return;
      Array.prototype.forEach.call(group.querySelectorAll('button'), function (b) {
        b.classList.remove('active');
      });
      btn.classList.add('active');
      state.hours = Number(btn.dataset.hours);
      state.bucket = Number(btn.dataset.bucket);
      state.openRows.clear();
      refresh();
    });

    $('#refreshBtn').addEventListener('click', refresh);

    document.addEventListener('visibilitychange', function () {
      if (!document.hidden) refresh();
    });
  }

  function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(function () {
      if (!document.hidden) refresh();
    }, POLL_MS);
  }

  function init() {
    bind();
    refresh();
    startPolling();
    // 等首次 refresh 拿到 health 后再决定是否连 SSE
    setTimeout(connectStream, 900);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
