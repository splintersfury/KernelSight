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

    /* Configs were authored independently, so their control ids share no
     * namespace: 'build' is an ordinal '1'..'6' on the KASLR page and a real
     * build number elsewhere, and 'drv' is a string enum on one page and a
     * boolean on another. Merging them silently mistypes values, so instead
     * each config projects a canonical platform onto its own control names
     * via fromPlatform(). A config without one is skipped rather than
     * evaluated against a state it never expected. */
    var platform = { build: 26100, hlat: true, kcet: true, hvci: true, admin: true, prims: true };
    var view = { layer: 'all', showClosed: true };

    function collect() {
      var out = [];
      (window.__ksnav || []).forEach(function (cfg) {
        if (typeof cfg.fromPlatform !== 'function') return;
        (cfg.techniques || []).forEach(function (t) {
          out.push({ t: t, cfg: cfg, defense: cfg.title || 'Unknown defense' });
        });
      });
      return out;
    }

    function controls() {
      var builds = [[19041, 'Windows 10 2004'], [22621, 'Windows 11 22H2'],
                    [26100, 'Windows 11 24H2'], [26200, 'Windows 11 25H2']].map(function (b) {
        return '<option value="' + b[0] + '"' + (b[0] === platform.build ? ' selected' : '') + '>' + b[1] + '</option>';
      }).join('');
      var layers = [['all', 'All layers'], ['kernel', 'Kernel layer'], ['user', 'User layer']].map(function (v) {
        return '<option value="' + v[0] + '"' + (v[0] === view.layer ? ' selected' : '') + '>' + v[1] + '</option>';
      }).join('');
      return '<div class="ksn__controls">' +
        '<div class="ksn__ctl"><span class="ksn__label">Build</span>' +
        '<select class="ksn__select" data-plat="build">' + builds + '</select></div>' +
        '<div class="ksn__ctl"><span class="ksn__label">Target layer</span>' +
        '<select class="ksn__select" data-view="layer">' + layers + '</select></div>' +
        '<div class="ksn__ctl ksn__ctl--wide"><span class="ksn__label">Platform and access</span>' +
        '<div class="ksn__checks">' +
        [['hlat', 'HLAT capable CPU'], ['kcet', 'kCET'], ['hvci', 'HVCI'],
         ['admin', 'admin'], ['prims', 'kernel read/write']].map(function (c) {
          return '<label class="ksn__chk"><input type="checkbox" data-plat="' + c[0] + '"' +
                 (platform[c[0]] ? ' checked' : '') + '> ' + c[1] + '</label>';
        }).join('') +
        '<label class="ksn__chk"><input type="checkbox" data-view="showClosed"' +
        (view.showClosed ? ' checked' : '') + '> show closed</label>' +
        '</div></div></div>';
    }

    function render() {
      var counts = { open: 0, gated: 0, closed: 0 };
      var rows = '';
      collect().forEach(function (entry) {
        var t = entry.t;
        var res;
        try { res = t.ev(entry.cfg.fromPlatform(platform)) || ['closed', '', '']; }
        catch (e) { res = ['closed', '', '']; }
        var status = res[0];
        if (counts[status] === undefined) counts[status] = 0;
        counts[status]++;
        if (view.layer !== 'all' && t.layer !== view.layer) return;
        if (!view.showClosed && status === 'closed') return;
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

      el.querySelectorAll('[data-plat]').forEach(function (n) {
        n.addEventListener('change', function () {
          var k = n.getAttribute('data-plat');
          platform[k] = (n.type === 'checkbox') ? n.checked : parseInt(n.value, 10);
          render();
        });
      });
      el.querySelectorAll('[data-view]').forEach(function (n) {
        n.addEventListener('change', function () {
          var k = n.getAttribute('data-view');
          view[k] = (n.type === 'checkbox') ? n.checked : n.value;
          render();
        });
      });
    }

    render();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount);
  else mount();
})();
