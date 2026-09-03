/* KernelSight mitigation Bypass Navigator — shared render engine.
 *
 * A page registers a navigator by pushing a config onto window.__ksnav:
 *   (window.__ksnav = window.__ksnav || []).push({ sel, title, sub, controls, techniques });
 * This script (loaded at end of body) mounts every queued config.
 *
 * config.controls: [{id, label, type:'select'|'checks', options, default, wide}]
 *   select option = [value, label];  checks option = [id, label]
 * config.techniques: [{name, cat, ev: state => [status, reqLabel, htmlReason]}]
 *   status is 'open' | 'gated' | 'closed'.  state has one key per control:
 *   select -> its value (string);  each check option id -> boolean.
 */
(function () {
  var DOT = { open: '#3fb950', gated: '#d29922', closed: 'var(--md-default-fg-color--lighter)' };

  function esc(s) { return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

  function buildControls(cfg) {
    var html = '<div class="ksn__controls">';
    cfg.controls.forEach(function (c) {
      html += '<div class="ksn__ctl' + (c.wide ? ' ksn__ctl--wide' : '') + '">';
      html += '<span class="ksn__label">' + esc(c.label) + '</span>';
      if (c.type === 'select') {
        html += '<select class="ksn__select" data-ctl="' + c.id + '">';
        c.options.forEach(function (o) {
          html += '<option value="' + esc(o[0]) + '"' + (String(o[0]) === String(c.default) ? ' selected' : '') + '>' + o[1] + '</option>';
        });
        html += '</select>';
      } else if (c.type === 'checks') {
        html += '<div class="ksn__checks">';
        c.options.forEach(function (o) {
          html += '<label class="ksn__chk"><input type="checkbox" data-chk="' + o[0] + '"' + (o[2] ? ' checked' : '') + '> ' + o[1] + '</label>';
        });
        html += '</div>';
      }
      html += '</div>';
    });
    html += '</div>';
    return html;
  }

  function readState(root, cfg) {
    var s = {};
    cfg.controls.forEach(function (c) {
      if (c.type === 'select') {
        var el = root.querySelector('[data-ctl="' + c.id + '"]');
        s[c.id] = el ? el.value : c.default;
      } else if (c.type === 'checks') {
        c.options.forEach(function (o) {
          var el = root.querySelector('[data-chk="' + o[0] + '"]');
          s[o[0]] = !!(el && el.checked);
        });
      }
    });
    return s;
  }

  function render(root, cfg) {
    var s = readState(root, cfg);
    var only = root.querySelector('[data-only]').checked;
    var list = root.querySelector('.ksn__list');
    var html = '', open = 0, shown = 0;
    cfg.techniques.forEach(function (t) {
      var r = t.ev(s), status = r[0], req = r[1], why = r[2];
      if (status === 'open') open++;
      if (only && status !== 'open') return;
      shown++;
      html += '<div class="ksn__row ksn__row--' + status + '">' +
        '<span class="ksn__rdot" style="background:' + DOT[status] + ';margin-top:6px"></span>' +
        '<div class="ksn__rmain"><div class="ksn__rname">' + esc(t.name) + '</div>' +
        '<div class="ksn__rcat">' + esc(t.cat) + '</div>' +
        '<div class="ksn__rwhy">' + why + '</div></div>' +
        '<div class="ksn__rside"><span class="ksn__pill ksn__pill--' + status + '">' + status + '</span>' +
        '<span class="ksn__req">' + esc(req) + '</span>' +
        (t.basis ? '<span class="ksn__basis">' + esc(t.basis) + ' &middot; ' + esc(t.asOf || '') + '</span>' : '') +
        '</div></div>';
    });
    list.innerHTML = html || '<div class="ksn__rwhy" style="padding:8px 2px">Nothing is open for this situation. Widen your access, add a primitive, or drop the &ldquo;only open&rdquo; filter.</div>';
    root.querySelector('[data-count]').textContent =
      open + ' of ' + cfg.techniques.length + ' open for this target' + (only ? ' · ' + shown + ' shown' : '');
  }

  function mount(cfg) {
    var root = document.querySelector(cfg.sel);
    if (!root || root.__ksnMounted) return;
    root.__ksnMounted = true;
    root.className = 'ksn';
    root.innerHTML =
      '<div class="ksn__head"><div class="ksn__title">' + esc(cfg.title || 'Bypass Navigator') + '</div>' +
      '<div class="ksn__sub">' + (cfg.sub || '') + '</div></div>' +
      buildControls(cfg) +
      '<div class="ksn__bar"><label class="ksn__chk ksn__chk--only"><input type="checkbox" data-only> Show only what\'s open</label>' +
      '<span class="ksn__count" data-count></span></div>' +
      '<div class="ksn__list"></div>' +
      '<div class="ksn__legend">' +
      '<span><i class="ksn__dot ksn__dot--open"></i>Open — usable as-is</span>' +
      '<span><i class="ksn__dot ksn__dot--gated"></i>Gated — needs more access or a primitive</span>' +
      '<span><i class="ksn__dot ksn__dot--closed"></i>Closed — blocked or restricted on this target</span></div>';
    root.addEventListener('change', function () { render(root, cfg); });
    render(root, cfg);
  }

  function drain() {
    var q = window.__ksnav || [];
    q.forEach(mount);
    // Replace the queue so any later push mounts immediately.
    window.__ksnav = { push: mount };
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', drain);
  } else {
    drain();
  }
})();
