/* KernelSight aggregate bypass matrix.
 * Reads every config pushed onto window.__ksnav and renders the union of
 * their techniques against one shared platform selector. A defense page
 * joins this matrix by registering a navigator config; nothing is restated. */
(function () {
  function mount() {
    var el = document.getElementById('ks-matrix');
    if (!el) return;

    var DOT = { open: '#3fb950', gated: '#d29922', closed: 'var(--md-default-fg-color--lighter)' };
    var BUILDS = [['19041', 'Windows 10 2004'], ['22621', 'Windows 11 22H2'],
                  ['26100', 'Windows 11 24H2'], ['26200', 'Windows 11 25H2']];

    function esc(s) {
      return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    /* Every navigator config declares its own controls, so the union of their
     * control ids is the state this page must supply. Defaults come from each
     * config, letting an ev() written for one page evaluate correctly here. */
    var state = { build: '26100' };
    (window.__ksnav || []).forEach(function (cfg) {
      (cfg.controls || []).forEach(function (c) {
        if (c.type === 'select' && state[c.id] === undefined) state[c.id] = c.default;
        if (c.type === 'checks') {
          (c.options || []).forEach(function (o) {
            if (state[o[0]] === undefined) state[o[0]] = !!o[2];
          });
        }
      });
    });
    state.layer = 'all';
    state.showClosed = true;

    function collect() {
      var out = [];
      (window.__ksnav || []).forEach(function (cfg) {
        (cfg.techniques || []).forEach(function (t) {
          out.push({ t: t, defense: cfg.title || 'Unknown defense' });
        });
      });
      return out;
    }

    function controls() {
      var builds = BUILDS.map(function (b) {
        return '<option value="' + b[0] + '"' + (b[0] === state.build ? ' selected' : '') + '>' + b[1] + '</option>';
      }).join('');
      var layers = [['all', 'All layers'], ['kernel', 'Kernel layer'], ['user', 'User layer']].map(function (v) {
        return '<option value="' + v[0] + '"' + (v[0] === state.layer ? ' selected' : '') + '>' + v[1] + '</option>';
      }).join('');
      return '<div class="ksn__controls">' +
        '<div class="ksn__ctl"><span class="ksn__label">Build</span>' +
        '<select class="ksn__select" data-ctl="build">' + builds + '</select></div>' +
        '<div class="ksn__ctl"><span class="ksn__label">Target layer</span>' +
        '<select class="ksn__select" data-ctl="layer">' + layers + '</select></div>' +
        '<div class="ksn__ctl ksn__ctl--wide"><span class="ksn__label">Display</span>' +
        '<div class="ksn__checks">' +
        '<label class="ksn__chk"><input type="checkbox" data-chk="showClosed"' +
        (state.showClosed ? ' checked' : '') + '> Show closed</label></div></div></div>';
    }

    function render() {
      var counts = { open: 0, gated: 0, closed: 0 };
      var rows = '';
      collect().forEach(function (entry) {
        var t = entry.t;
        var res;
        try { res = t.ev(state) || ['closed', '', '']; } catch (e) { res = ['closed', '', '']; }
        var status = res[0];
        if (counts[status] === undefined) counts[status] = 0;
        counts[status]++;
        if (state.layer !== 'all' && t.layer !== state.layer) return;
        if (!state.showClosed && status === 'closed') return;
        rows += '<div class="ksn__row' + (status === 'closed' ? ' ksn__row--closed' : '') + '">' +
          '<div class="ksn__rdot" style="background:' + DOT[status] + '"></div>' +
          '<div class="ksn__rmain"><div class="ksn__rname">' + esc(t.name) + '</div>' +
          '<div class="ksn__rcat">' + esc(entry.defense) + '</div>' +
          '<div class="ksn__rwhy">' + (res[2] || '') + '</div></div>' +
          '<div class="ksn__rside">' +
          '<span class="ksn__pill ksn__pill--' + status + '">' + status + '</span>' +
          (t.basis ? '<span class="ksn__basis">' + esc(t.basis) + ' &middot; ' + esc(t.asOf || '') + '</span>' : '') +
          '</div></div>';
      });

      el.innerHTML = '<div class="ksn">' + controls() +
        '<div class="ksn__bar"><span class="ksn__count">' +
        counts.open + ' open, ' + counts.gated + ' gated, ' + counts.closed + ' closed' +
        '</span></div><div class="ksn__list">' + rows + '</div></div>';

      el.querySelectorAll('[data-ctl]').forEach(function (n) {
        n.addEventListener('change', function () { state[n.getAttribute('data-ctl')] = n.value; render(); });
      });
      el.querySelectorAll('[data-chk]').forEach(function (n) {
        n.addEventListener('change', function () { state[n.getAttribute('data-chk')] = n.checked; render(); });
      });
    }

    render();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount);
  else mount();
})();
