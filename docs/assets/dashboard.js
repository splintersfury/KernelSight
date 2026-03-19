/**
 * KernelSight Interactive Dashboard
 * Vanilla JS — no dependencies. Renders into #ks-dashboard.
 */
(function () {
  "use strict";

  var DATA_URL = "assets/dashboard-data.json";
  var root = document.getElementById("ks-dashboard");
  if (!root) return;

  var state = {
    data: null,
    search: "",
    filterItw: false,
    filterPoc: false,
    filterWriteup: false,
    filterDriver: "",
    filterVulnClass: "",
    sortCol: "id",
    sortAsc: true,
    rows: [],
  };

  /* ── Fetch & Init ────────────────────────────────────────────── */

  fetch(DATA_URL)
    .then(function (r) {
      if (!r.ok) throw new Error("Failed to load dashboard data");
      return r.json();
    })
    .then(function (data) {
      state.data = data;
      render();
    })
    .catch(function (err) {
      root.innerHTML =
        '<p style="color:var(--ks-badge-itw)">Failed to load dashboard data: ' +
        err.message +
        "</p>";
    });

  /* ── Render ──────────────────────────────────────────────────── */

  function render() {
    root.innerHTML = "";
    renderStatsBar();
    renderMatrix();
    renderControls();
    renderTable();
    applyFilters();
    animateCounters();
  }

  /* ── Stats Bar ───────────────────────────────────────────────── */

  function renderStatsBar() {
    var s = state.data.stats;
    var bar = el("div", "ks-stats-bar");
    bar.appendChild(statCard(s.total_cves, "Total CVEs"));
    bar.appendChild(statCard(s.total_drivers, "Drivers"));
    bar.appendChild(statCard(s.itw_count, "Exploited ITW"));
    bar.appendChild(statCard(s.poc_count, "PoC Available"));
    root.appendChild(bar);
  }

  function statCard(value, label) {
    var card = el("div", "ks-stat-card");
    var num = el("span", "ks-stat-number");
    num.setAttribute("data-target", value);
    num.textContent = "0";
    var lbl = el("span", "ks-stat-label");
    lbl.textContent = label;
    card.appendChild(num);
    card.appendChild(lbl);
    return card;
  }

  function animateCounters() {
    var counters = root.querySelectorAll(".ks-stat-number");
    counters.forEach(function (counter) {
      var target = parseInt(counter.getAttribute("data-target"), 10);
      var duration = 600;
      var start = performance.now();
      function step(now) {
        var progress = Math.min((now - start) / duration, 1);
        var eased = 1 - Math.pow(1 - progress, 3);
        counter.textContent = Math.round(eased * target);
        if (progress < 1) requestAnimationFrame(step);
      }
      requestAnimationFrame(step);
    });
  }

  /* ── Heat Matrix ─────────────────────────────────────────────── */

  function renderMatrix() {
    var m = state.data.matrix;
    if (!m.rows.length || !m.cols.length) return;

    var section = el("div", "ks-matrix-section");
    var title = el("div", "ks-matrix-title");
    title.textContent = "Driver x Vulnerability Class Matrix";
    section.appendChild(title);

    var scroll = el("div", "ks-matrix-scroll");
    var grid = el("div", "ks-matrix");

    var colCount = m.cols.length + 1;
    grid.style.gridTemplateColumns = "minmax(120px, auto) " + "repeat(" + m.cols.length + ", minmax(60px, 1fr))";

    // Corner cell
    var corner = el("div", "ks-matrix-header corner");
    grid.appendChild(corner);

    // Column headers
    m.cols.forEach(function (vc) {
      var h = el("div", "ks-matrix-header col-header");
      h.textContent = formatVulnClass(vc);
      h.title = vc;
      grid.appendChild(h);
    });

    // Rows
    m.rows.forEach(function (driver) {
      var rh = el("div", "ks-matrix-header row-header");
      rh.textContent = driver;
      rh.title = driver;
      grid.appendChild(rh);

      m.cols.forEach(function (vc) {
        var key = driver + "|" + vc;
        var cell = el("div", "ks-matrix-cell");
        var info = m.cells[key];
        var count = info ? info.count : 0;
        var itw = info ? info.itw : 0;

        cell.classList.add(heatLevel(count));
        if (count > 0) {
          cell.textContent = count;
        }
        if (itw > 0) {
          var dot = el("span", "ks-itw-dot");
          cell.appendChild(dot);
        }

        cell.title = driver + " / " + vc + ": " + count + " CVE" + (count !== 1 ? "s" : "") + (itw ? " (" + itw + " ITW)" : "");

        if (count > 0) {
          cell.addEventListener("click", (function (d, v) {
            return function () {
              state.filterDriver = d;
              state.filterVulnClass = v;
              state.search = "";
              updateControlsUI();
              applyFilters();
              scrollToTable();
            };
          })(driver, vc));
        }

        grid.appendChild(cell);
      });
    });

    scroll.appendChild(grid);
    section.appendChild(scroll);
    root.appendChild(section);
  }

  function heatLevel(count) {
    if (count === 0) return "ks-heat-0";
    if (count === 1) return "ks-heat-1";
    if (count === 2) return "ks-heat-2";
    if (count <= 4) return "ks-heat-3";
    return "ks-heat-4";
  }

  function formatVulnClass(slug) {
    return slug.replace(/-/g, " ").replace(/\b\w/g, function (c) {
      return c.toUpperCase();
    });
  }

  /* ── Controls ────────────────────────────────────────────────── */

  function renderControls() {
    var controls = el("div", "ks-controls");
    controls.id = "ks-controls";

    // Search row
    var searchRow = el("div", "ks-search-row");
    var input = el("input", "ks-search-input");
    input.type = "text";
    input.placeholder = "Search CVE ID, driver, description, vuln class...";
    input.addEventListener("input", function () {
      state.search = this.value.toLowerCase();
      applyFilters();
    });
    searchRow.appendChild(input);
    controls.appendChild(searchRow);

    // Filter chips
    var chips = el("div", "ks-filter-chips");
    chips.id = "ks-filter-chips";

    chips.appendChild(chip("Exploited ITW", "filterItw"));
    chips.appendChild(chip("Has PoC", "filterPoc"));
    chips.appendChild(chip("Has Writeup", "filterWriteup"));

    var clearBtn = el("button", "ks-chip-clear");
    clearBtn.textContent = "Clear filters";
    clearBtn.addEventListener("click", function () {
      state.filterItw = false;
      state.filterPoc = false;
      state.filterWriteup = false;
      state.filterDriver = "";
      state.filterVulnClass = "";
      state.search = "";
      updateControlsUI();
      applyFilters();
    });
    chips.appendChild(clearBtn);

    controls.appendChild(chips);

    // Active filter display
    var activeFilter = el("div", "ks-result-count");
    activeFilter.id = "ks-active-filter";
    controls.appendChild(activeFilter);

    // Result count
    var resultCount = el("div", "ks-result-count");
    resultCount.id = "ks-result-count";
    controls.appendChild(resultCount);

    // Export buttons
    var exports = el("div", "ks-export-row");
    var csvBtn = el("button", "ks-export-btn");
    csvBtn.textContent = "Export CSV";
    csvBtn.addEventListener("click", exportCSV);
    var jsonBtn = el("button", "ks-export-btn");
    jsonBtn.textContent = "Export JSON";
    jsonBtn.addEventListener("click", exportJSON);
    exports.appendChild(csvBtn);
    exports.appendChild(jsonBtn);
    controls.appendChild(exports);

    root.appendChild(controls);
  }

  function chip(label, stateKey) {
    var btn = el("button", "ks-chip");
    btn.textContent = label;
    btn.setAttribute("data-filter", stateKey);
    btn.addEventListener("click", function () {
      state[stateKey] = !state[stateKey];
      this.classList.toggle("active", state[stateKey]);
      applyFilters();
    });
    return btn;
  }

  function updateControlsUI() {
    var searchInput = root.querySelector(".ks-search-input");
    if (searchInput) searchInput.value = state.search;

    root.querySelectorAll(".ks-chip").forEach(function (c) {
      var key = c.getAttribute("data-filter");
      if (key) c.classList.toggle("active", state[key]);
    });
  }

  /* ── Table ───────────────────────────────────────────────────── */

  function renderTable() {
    var wrap = el("div", "ks-table-wrap");
    wrap.id = "ks-table-wrap";
    var table = el("table", "ks-cve-table");

    // Header
    var thead = document.createElement("thead");
    var hr = document.createElement("tr");
    var columns = [
      { key: "id", label: "CVE ID" },
      { key: "driver", label: "Driver" },
      { key: "vuln_class", label: "Vuln Class" },
      { key: "badges", label: "Status", sortable: false },
    ];

    columns.forEach(function (col) {
      var th = document.createElement("th");
      th.textContent = col.label;
      if (col.sortable !== false) {
        var arrow = el("span", "sort-arrow");
        arrow.textContent = state.sortCol === col.key ? (state.sortAsc ? "\u25B2" : "\u25BC") : "\u25B2";
        th.appendChild(arrow);
        if (state.sortCol === col.key) th.classList.add("sorted");
        th.addEventListener("click", (function (k) {
          return function () {
            if (state.sortCol === k) {
              state.sortAsc = !state.sortAsc;
            } else {
              state.sortCol = k;
              state.sortAsc = true;
            }
            sortAndUpdate();
          };
        })(col.key));
      }
      hr.appendChild(th);
    });
    thead.appendChild(hr);
    table.appendChild(thead);

    // Body
    var tbody = document.createElement("tbody");
    tbody.id = "ks-tbody";

    state.data.cves.forEach(function (cve, idx) {
      var tr = document.createElement("tr");
      tr.setAttribute("data-idx", idx);

      // CVE ID
      var tdId = document.createElement("td");
      if (cve.case_study) {
        var a = document.createElement("a");
        a.href = cve.case_study;
        a.textContent = cve.id;
        tdId.appendChild(a);
      } else {
        tdId.textContent = cve.id;
      }
      tr.appendChild(tdId);

      // Driver
      var tdDriver = document.createElement("td");
      tdDriver.textContent = cve.driver;
      tdDriver.classList.add("clickable");
      tdDriver.title = "Filter by " + cve.driver;
      tdDriver.addEventListener("click", (function (d) {
        return function () {
          state.filterDriver = state.filterDriver === d ? "" : d;
          state.filterVulnClass = "";
          updateActiveFilter();
          applyFilters();
        };
      })(cve.driver));
      tr.appendChild(tdDriver);

      // Vuln class
      var tdVc = document.createElement("td");
      tdVc.textContent = formatVulnClass(cve.vuln_class);
      tdVc.classList.add("clickable");
      tdVc.title = "Filter by " + cve.vuln_class;
      tdVc.addEventListener("click", (function (vc) {
        return function () {
          state.filterVulnClass = state.filterVulnClass === vc ? "" : vc;
          state.filterDriver = "";
          updateActiveFilter();
          applyFilters();
        };
      })(cve.vuln_class));
      tr.appendChild(tdVc);

      // Badges
      var tdBadges = document.createElement("td");
      var badgesDiv = el("div", "ks-badges-cell");
      if (cve.itw) badgesDiv.appendChild(badge("ITW", "ks-badge-itw"));
      if (cve.has_poc) badgesDiv.appendChild(badge("PoC", "ks-badge-poc"));
      if (cve.has_writeup) badgesDiv.appendChild(badge("Writeup", "ks-badge-writeup"));
      tdBadges.appendChild(badgesDiv);
      tr.appendChild(tdBadges);

      tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    wrap.appendChild(table);
    root.appendChild(wrap);

    state.rows = Array.from(tbody.querySelectorAll("tr"));
  }

  function badge(text, cls) {
    var span = el("span", "ks-badge " + cls);
    span.textContent = text;
    return span;
  }

  /* ── Filter Logic ────────────────────────────────────────────── */

  function applyFilters() {
    var cves = state.data.cves;
    var visible = 0;

    state.rows.forEach(function (tr) {
      var idx = parseInt(tr.getAttribute("data-idx"), 10);
      var cve = cves[idx];
      var show = true;

      // Text search
      if (state.search) {
        var hay = (cve.id + " " + cve.driver + " " + cve.description + " " + cve.vuln_class).toLowerCase();
        if (hay.indexOf(state.search) === -1) show = false;
      }

      // Boolean filters
      if (state.filterItw && !cve.itw) show = false;
      if (state.filterPoc && !cve.has_poc) show = false;
      if (state.filterWriteup && !cve.has_writeup) show = false;

      // Driver filter
      if (state.filterDriver && cve.driver !== state.filterDriver) show = false;

      // Vuln class filter
      if (state.filterVulnClass && cve.vuln_class !== state.filterVulnClass) show = false;

      tr.classList.toggle("hidden", !show);
      if (show) visible++;
    });

    updateResultCount(visible, cves.length);
    updateActiveFilter();
  }

  function updateResultCount(visible, total) {
    var el = document.getElementById("ks-result-count");
    if (el) {
      el.textContent = "Showing " + visible + " of " + total + " CVEs";
    }
  }

  function updateActiveFilter() {
    var afEl = document.getElementById("ks-active-filter");
    if (!afEl) return;
    var parts = [];
    if (state.filterDriver) parts.push("Driver: " + state.filterDriver);
    if (state.filterVulnClass) parts.push("Class: " + formatVulnClass(state.filterVulnClass));
    afEl.textContent = parts.length ? parts.join("  |  ") : "";
  }

  /* ── Sort Logic ──────────────────────────────────────────────── */

  function sortAndUpdate() {
    var cves = state.data.cves;
    var col = state.sortCol;
    var asc = state.sortAsc;

    state.rows.sort(function (a, b) {
      var ai = parseInt(a.getAttribute("data-idx"), 10);
      var bi = parseInt(b.getAttribute("data-idx"), 10);
      var av = cves[ai][col] || "";
      var bv = cves[bi][col] || "";
      if (av < bv) return asc ? -1 : 1;
      if (av > bv) return asc ? 1 : -1;
      return 0;
    });

    var tbody = document.getElementById("ks-tbody");
    state.rows.forEach(function (tr) {
      tbody.appendChild(tr);
    });

    // Update header arrows
    root.querySelectorAll(".ks-cve-table th").forEach(function (th) {
      th.classList.remove("sorted");
      var arrow = th.querySelector(".sort-arrow");
      if (arrow) arrow.textContent = "\u25B2";
    });

    var headers = root.querySelectorAll(".ks-cve-table th");
    var colIdx = col === "id" ? 0 : col === "driver" ? 1 : col === "vuln_class" ? 2 : -1;
    if (colIdx >= 0 && headers[colIdx]) {
      headers[colIdx].classList.add("sorted");
      var arrow = headers[colIdx].querySelector(".sort-arrow");
      if (arrow) arrow.textContent = asc ? "\u25B2" : "\u25BC";
    }
  }

  /* ── Export ──────────────────────────────────────────────────── */

  function getVisibleCves() {
    var cves = state.data.cves;
    var result = [];
    state.rows.forEach(function (tr) {
      if (!tr.classList.contains("hidden")) {
        var idx = parseInt(tr.getAttribute("data-idx"), 10);
        result.push(cves[idx]);
      }
    });
    return result;
  }

  function exportCSV() {
    var visible = getVisibleCves();
    var headers = ["CVE ID", "Driver", "Vuln Class", "Description", "ITW", "PoC", "Writeup", "MSRC URL"];
    var lines = [headers.join(",")];
    visible.forEach(function (cve) {
      var row = [
        csvEscape(cve.id),
        csvEscape(cve.driver),
        csvEscape(cve.vuln_class),
        csvEscape(cve.description),
        cve.itw ? "Yes" : "No",
        cve.has_poc ? "Yes" : "No",
        cve.has_writeup ? "Yes" : "No",
        csvEscape(cve.references.msrc || ""),
      ];
      lines.push(row.join(","));
    });
    download("kernelsight-cves.csv", "text/csv;charset=utf-8;", lines.join("\n"));
  }

  function exportJSON() {
    var visible = getVisibleCves();
    var json = JSON.stringify(visible, null, 2);
    download("kernelsight-cves.json", "application/json;charset=utf-8;", json);
  }

  function csvEscape(val) {
    if (!val) return '""';
    var s = String(val);
    if (s.indexOf(",") !== -1 || s.indexOf('"') !== -1 || s.indexOf("\n") !== -1) {
      return '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
  }

  function download(filename, mime, content) {
    var blob = new Blob([content], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  /* ── Helpers ─────────────────────────────────────────────────── */

  function el(tag, className) {
    var e = document.createElement(tag);
    if (className) e.className = className;
    return e;
  }

  function scrollToTable() {
    var wrap = document.getElementById("ks-table-wrap");
    if (wrap) wrap.scrollIntoView({ behavior: "smooth", block: "start" });
  }
})();
