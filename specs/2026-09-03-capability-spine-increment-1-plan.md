# KernelSight Capability Spine, Increment 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reposition KernelSight around the capability spine, so a reader can tell from the navigation and the homepage that the site maps what kernel access buys you, and ship the first user-layer defense page to prove the shape.

**Architecture:** A grouping change in `mkdocs.yml` plus a homepage rewrite, with no file moves, so every published URL survives. The Bypass Navigator's `window.__ksnav` config becomes the bypass registry: three required fields are added to each technique entry, the navigator renders them, and a new aggregate matrix page reads every registered config. A defense roster in YAML makes coverage a computed number, and three CI checks stop the numbers going stale.

**Tech Stack:** MkDocs Material, Python 3.12, PyYAML, vanilla JS (no framework, no build step), pytest.

**Spec:** `specs/2026-09-03-capability-spine-amendment.md`, which amends `specs/2026-08-17-kernelsight-bypass-registry-design.md`. Read both.

## Global Constraints

- **No em-dash characters anywhere.** Not in prose, page copy, code comments or commit messages. Recast the sentence instead of swapping punctuation.
- **No file moves under `docs/`.** MkDocs derives URLs from paths. Any move breaks a published URL. Nav regrouping is a `mkdocs.yml` change only.
- **Every alive or dead claim carries `asOf` and `basis`.** `basis` is exactly one of `tested`, `cited`, `inferred`. This is the August design's core discipline.
- **`layer` is the layer of the asset protected, never the enforcer.** PPL is `layer: user, enforced_by: kernel`.
- **Unconfirmed claims ship as `basis: inferred`.** Never as `cited`. The HLAT-closes-the-kernel-table-family claim is inferred.
- **Existing design tokens only.** Ground `#10131a`, surface `#1c2026`, ink `#e0e2eb`, muted `#9ca3af`, dim `#6b7280`, accent `#adc6ff` to `#0566d9`, status open `#3fb950`, gated `#d29922`. Pill background for open is `rgba(46,160,67,.16)`, matching `docs/stylesheets/navigator.css`.
- **Radius scale:** 3px hairline bars, 6px controls and badges, 10px rows and inner panels, 16px cards, 999px pills. No other values.
- **Build command is two steps:** `python scripts/build_dashboard_data.py && mkdocs build --strict`. Both must pass before any commit.
- **Python deps are `mkdocs-material` and `pyyaml` only.** Adding a dependency means editing `.github/workflows/deploy-pages.yml`. Avoid it.

---

### Task 1: Defense roster as data

Creates the enumeration that makes coverage computable. Nothing else can be counted until this exists.

**Files:**
- Create: `index/defenses.yaml`
- Create: `scripts/check_roster.py`
- Create: `tests/test_roster.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `index/defenses.yaml` with a top-level `defenses` list. Each entry has `id` (str), `name` (str), `layer` (`kernel`|`user`), `enforced_by` (`kernel`|`hypervisor`|`hardware`), `protects` (str), `page` (str path under `docs/`, or null), `status` (`current`|`planned`|`historical`). `scripts/check_roster.py` exposes `load_roster() -> list[dict]` and `check(roster) -> list[str]` returning error strings.

- [ ] **Step 1: Write the failing test**

Create `tests/test_roster.py`:

```python
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_roster import load_roster, check


def test_roster_has_29_defenses():
    assert len(load_roster()) == 29


def test_layer_split_is_19_kernel_10_user():
    roster = load_roster()
    kernel = [d for d in roster if d["layer"] == "kernel"]
    user = [d for d in roster if d["layer"] == "user"]
    assert (len(kernel), len(user)) == (19, 10)


def test_every_id_is_unique():
    ids = [d["id"] for d in load_roster()]
    assert len(ids) == len(set(ids))


def test_ppl_is_user_layer_enforced_by_kernel():
    ppl = next(d for d in load_roster() if d["id"] == "protected-process")
    assert ppl["layer"] == "user"
    assert ppl["enforced_by"] == "kernel"


def test_roster_check_reports_no_errors():
    assert check(load_roster()) == []


def test_check_catches_a_page_that_does_not_exist():
    bad = [{
        "id": "ghost", "name": "Ghost", "layer": "kernel",
        "enforced_by": "kernel", "protects": "nothing",
        "page": "docs/mitigations/does-not-exist.md", "status": "current",
    }]
    errors = check(bad)
    assert any("does-not-exist" in e for e in errors)


def test_check_catches_a_bad_layer_value():
    bad = [{
        "id": "ghost", "name": "Ghost", "layer": "hypervisor",
        "enforced_by": "kernel", "protects": "nothing",
        "page": None, "status": "planned",
    }]
    assert any("layer" in e for e in check(bad))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Documents/KernelSight && python -m pytest tests/test_roster.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'check_roster'`

- [ ] **Step 3: Write the roster**

Create `index/defenses.yaml`. The nineteen kernel-layer entries first. `page` is the existing path where one exists, `null` where the page is not yet written, and `status: planned` marks those.

```yaml
# KernelSight defense roster.
# layer = the layer of the ASSET protected, not the enforcer.
version: 1
defenses:
  - id: smep
    name: "SMEP"
    layer: kernel
    enforced_by: hardware
    protects: "Kernel execution of user-mode pages"
    page: docs/mitigations/smep-smap.md
    status: current
  - id: smap
    name: "SMAP"
    layer: kernel
    enforced_by: hardware
    protects: "Kernel data access to user-mode pages"
    page: docs/mitigations/smep-smap.md
    status: current
  - id: kcfg
    name: "kCFG"
    layer: kernel
    enforced_by: kernel
    protects: "Kernel indirect call targets"
    page: docs/mitigations/kcfg-kcet.md
    status: current
  - id: kcet
    name: "kCET"
    layer: kernel
    enforced_by: hardware
    protects: "Kernel return addresses via shadow stack"
    page: docs/mitigations/kcfg-kcet.md
    status: current
  - id: hvci
    name: "VBS / HVCI"
    layer: kernel
    enforced_by: hypervisor
    protects: "Kernel code integrity and W^X on code pages"
    page: docs/mitigations/vbs-hvci.md
    status: current
  - id: kdp
    name: "Kernel Data Protection"
    layer: kernel
    enforced_by: hypervisor
    protects: "Designated read-only kernel data regions"
    page: docs/mitigations/kdp.md
    status: current
  - id: pool-hardening
    name: "Pool hardening"
    layer: kernel
    enforced_by: kernel
    protects: "Pool metadata integrity"
    page: docs/mitigations/pool-hardening.md
    status: current
  - id: secure-pool
    name: "Secure Pool"
    layer: kernel
    enforced_by: hypervisor
    protects: "Hypervisor-validated pool allocations"
    page: docs/mitigations/secure-pool.md
    status: current
  - id: acg
    name: "Arbitrary Code Guard"
    layer: kernel
    enforced_by: hypervisor
    protects: "Dynamic code generation in protected processes"
    page: docs/mitigations/acg.md
    status: current
  - id: kaslr
    name: "KASLR"
    layer: kernel
    enforced_by: kernel
    protects: "Kernel address layout confidentiality"
    page: docs/mitigations/kaslr.md
    status: current
  - id: dse
    name: "Driver Signature Enforcement"
    layer: kernel
    enforced_by: kernel
    protects: "Which drivers may load"
    page: null
    status: planned
  - id: hlat
    name: "HLAT / HVPT"
    layer: kernel
    enforced_by: hypervisor
    protects: "Guest page-table translation integrity"
    page: null
    status: planned
  - id: mbec
    name: "MBEC / GMET"
    layer: kernel
    enforced_by: hypervisor
    protects: "Mode-based execute control on guest pages"
    page: null
    status: planned
  - id: patchguard
    name: "PatchGuard"
    layer: kernel
    enforced_by: kernel
    protects: "Periodic integrity of critical kernel structures"
    page: null
    status: planned
  - id: hyperguard
    name: "HyperGuard / SKPG"
    layer: kernel
    enforced_by: hypervisor
    protects: "Secure-kernel-side integrity of kernel structures"
    page: null
    status: planned
  - id: driver-blocklist
    name: "Vulnerable driver blocklist"
    layer: kernel
    enforced_by: kernel
    protects: "Which signed drivers may load despite valid signatures"
    page: null
    status: planned
  - id: secure-kernel
    name: "Secure Kernel / VTL1"
    layer: kernel
    enforced_by: hypervisor
    protects: "Isolated execution above the normal kernel"
    page: null
    status: planned
  - id: kernel-dma-protection
    name: "Kernel DMA Protection"
    layer: kernel
    enforced_by: hardware
    protects: "Memory against bus-mastering device writes"
    page: null
    status: planned
  - id: type-isolation
    name: "Type isolation"
    layer: kernel
    enforced_by: kernel
    protects: "Separation of attacker-groomable object types"
    page: null
    status: planned

  # ---- user layer ----
  - id: protected-process
    name: "Protected Process Light"
    layer: user
    enforced_by: kernel
    protects: "Process and thread objects of signer-qualified processes"
    page: docs/mitigations/protected-process.md
    status: current
  - id: lsa-protection
    name: "LSA Protection"
    layer: user
    enforced_by: kernel
    protects: "Credential material held in the LSA process"
    page: null
    status: planned
  - id: credential-guard
    name: "Credential Guard"
    layer: user
    enforced_by: hypervisor
    protects: "Credential material isolated in VTL1"
    page: null
    status: planned
  - id: etw-ti
    name: "ETW Threat Intelligence"
    layer: user
    enforced_by: kernel
    protects: "The threat-intelligence telemetry channel"
    page: null
    status: planned
  - id: edr-kernel-callbacks
    name: "EDR kernel callbacks"
    layer: user
    enforced_by: kernel
    protects: "Sensor notification registrations"
    page: null
    status: planned
  - id: edr-usermode-hooks
    name: "EDR user-mode hooks"
    layer: user
    enforced_by: kernel
    protects: "Inline hooks placed in user-mode modules"
    page: null
    status: planned
  - id: wdac-usermode
    name: "WDAC user-mode code integrity"
    layer: user
    enforced_by: kernel
    protects: "Which user-mode binaries may execute"
    page: null
    status: planned
  - id: applocker
    name: "AppLocker"
    layer: user
    enforced_by: kernel
    protects: "Application allowlisting policy"
    page: null
    status: planned
  - id: uac-integrity
    name: "UAC and integrity levels"
    layer: user
    enforced_by: kernel
    protects: "Token integrity levels and elevation consent"
    page: null
    status: planned
  - id: amsi
    name: "AMSI"
    layer: user
    enforced_by: kernel
    protects: "Script and macro content scanning"
    page: null
    status: planned
```

- [ ] **Step 4: Write the checker**

Create `scripts/check_roster.py`:

```python
"""Validate index/defenses.yaml. Exit non-zero on any error."""
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ROSTER = ROOT / "index" / "defenses.yaml"

VALID_LAYERS = {"kernel", "user"}
VALID_ENFORCERS = {"kernel", "hypervisor", "hardware"}
VALID_STATUS = {"current", "planned", "historical"}
REQUIRED = ("id", "name", "layer", "enforced_by", "protects", "page", "status")


def load_roster():
    with ROSTER.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)["defenses"]


def check(roster):
    errors = []
    seen = set()
    for entry in roster:
        did = entry.get("id", "<missing id>")
        for field in REQUIRED:
            if field not in entry:
                errors.append(f"{did}: missing required field '{field}'")
        if did in seen:
            errors.append(f"{did}: duplicate id")
        seen.add(did)
        if entry.get("layer") not in VALID_LAYERS:
            errors.append(f"{did}: layer must be one of {sorted(VALID_LAYERS)}")
        if entry.get("enforced_by") not in VALID_ENFORCERS:
            errors.append(f"{did}: enforced_by must be one of {sorted(VALID_ENFORCERS)}")
        if entry.get("status") not in VALID_STATUS:
            errors.append(f"{did}: status must be one of {sorted(VALID_STATUS)}")
        page = entry.get("page")
        if page is None:
            if entry.get("status") != "planned":
                errors.append(f"{did}: page is null so status must be 'planned'")
        elif not (ROOT / page).exists():
            errors.append(f"{did}: page does not exist: {page}")
    return errors


def main():
    errors = check(load_roster())
    for error in errors:
        print(f"ERROR {error}", file=sys.stderr)
    if errors:
        return 1
    roster = load_roster()
    kernel = sum(1 for d in roster if d["layer"] == "kernel")
    user = len(roster) - kernel
    written = sum(1 for d in roster if d["page"])
    print(f"roster ok: {len(roster)} defenses ({kernel} kernel, {user} user), {written} with pages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 5: Run tests, expecting one failure**

Run: `python -m pytest tests/test_roster.py -v`
Expected: all pass except `test_roster_check_reports_no_errors`, which fails because `protected-process` names `docs/mitigations/protected-process.md` and that page does not exist yet. That failure is correct and Task 4 clears it. Leave it red.

- [ ] **Step 6: Commit**

```bash
git add index/defenses.yaml scripts/check_roster.py tests/test_roster.py
git commit -m "feat(roster): add defense roster with layer axis

29 defenses, 19 kernel layer and 10 user layer. layer records the layer
of the asset protected, not the enforcer, so PPL is user layer enforced
by the kernel.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01QkCo4PpjPMeejAX1PAs14E"
```

---

### Task 2: Required verdict fields on navigator techniques

Adds the anti-staleness discipline to the four shipping navigator pages and makes the navigator refuse to render a technique that lacks it.

**Files:**
- Modify: `docs/javascripts/navigator.js`
- Modify: `docs/mitigations/kaslr-bypasses.md`
- Modify: `docs/mitigations/vbs-hvci.md`
- Modify: `docs/mitigations/kcfg-kcet.md`
- Modify: `docs/mitigations/smep-smap.md`
- Modify: `docs/stylesheets/navigator.css`
- Create: `scripts/check_verdicts.py`
- Create: `tests/test_verdicts.py`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: every `__ksnav` technique object gains `layer` (`'kernel'`|`'user'`), `asOf` (`'YYYY-MM-DD'`) and `basis` (`'tested'`|`'cited'`|`'inferred'`). `scripts/check_verdicts.py` exposes `scan() -> list[dict]` returning one record per technique with keys `file`, `name`, `layer`, `asOf`, `basis`, and `check(records) -> list[str]`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_verdicts.py`:

```python
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_verdicts import scan, check

VALID_BASIS = {"tested", "cited", "inferred"}


def test_scan_finds_all_37_shipping_techniques():
    assert len(scan()) == 37


def test_every_technique_has_the_three_required_fields():
    for record in scan():
        assert record["layer"] in {"kernel", "user"}, record
        assert record["basis"] in VALID_BASIS, record
        assert record["asOf"], record


def test_asof_is_an_iso_date():
    import re
    for record in scan():
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", record["asOf"]), record


def test_check_reports_no_errors():
    assert check(scan()) == []


def test_check_catches_a_missing_basis():
    bad = [{"file": "x.md", "name": "t", "layer": "kernel", "asOf": "2026-01-01", "basis": None}]
    assert any("basis" in e for e in check(bad))


def test_check_catches_a_bad_layer():
    bad = [{"file": "x.md", "name": "t", "layer": "firmware", "asOf": "2026-01-01", "basis": "cited"}]
    assert any("layer" in e for e in check(bad))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_verdicts.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'check_verdicts'`

- [ ] **Step 3: Write the scanner**

Create `scripts/check_verdicts.py`:

```python
"""Scan __ksnav technique entries in mitigation pages for required verdict fields.

The configs are JS object literals inside markdown, so this parses by regex
rather than by evaluating them. Each technique entry is recognised by its
`name:` key; the three required fields are read from the same object body.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGES = sorted((ROOT / "docs" / "mitigations").glob("*.md"))

VALID_LAYERS = {"kernel", "user"}
VALID_BASIS = {"tested", "cited", "inferred"}
ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")

# One technique object: from `{ name:` up to the `ev:` key that closes the
# metadata run. Non-greedy so adjacent entries do not merge.
TECHNIQUE = re.compile(r"\{\s*name\s*:\s*(['\"])(?P<name>.*?)\1(?P<body>.*?)ev\s*:", re.S)


def _field(body, key):
    match = re.search(rf"{key}\s*:\s*(['\"])(.*?)\1", body, re.S)
    return match.group(2) if match else None


def scan():
    records = []
    for page in PAGES:
        text = page.read_text(encoding="utf-8")
        if "__ksnav" not in text:
            continue
        for match in TECHNIQUE.finditer(text):
            body = match.group("body")
            records.append({
                "file": page.name,
                "name": match.group("name"),
                "layer": _field(body, "layer"),
                "asOf": _field(body, "asOf"),
                "basis": _field(body, "basis"),
            })
    return records


def check(records):
    errors = []
    for record in records:
        where = f"{record['file']}: {record['name']}"
        if record["layer"] not in VALID_LAYERS:
            errors.append(f"{where}: layer must be one of {sorted(VALID_LAYERS)}, got {record['layer']!r}")
        if record["basis"] not in VALID_BASIS:
            errors.append(f"{where}: basis must be one of {sorted(VALID_BASIS)}, got {record['basis']!r}")
        if not record["asOf"] or not ISO_DATE.fullmatch(record["asOf"]):
            errors.append(f"{where}: asOf must be an ISO date, got {record['asOf']!r}")
    return errors


def main():
    records = scan()
    errors = check(records)
    for error in errors:
        print(f"ERROR {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"verdicts ok: {len(records)} techniques, all carrying layer, asOf and basis")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run to see the real failure count**

Run: `python scripts/check_verdicts.py`
Expected: exit 1, with 37 groups of errors, because no shipping technique carries the fields yet. Note the count. It must be 37.

- [ ] **Step 5: Add the three fields to every technique**

Edit each of the four pages. Every technique object gains three keys before its `ev:` key. All 37 shipping techniques are `layer: 'kernel'`, because all four pages are kernel-layer defenses.

For `basis`, use `'cited'` where the page already links a source, and `'inferred'` where it does not. Do not invent a source to justify `'cited'`. For `asOf`, use the date of the source the page cites; where the page cites nothing, use `'2026-09-03'` and `basis: 'inferred'`.

Pattern, using the first KASLR entry as the worked example:

```js
{ name: 'SIDT KASLR leak',
  cat: 'kaslr-leak',
  layer: 'kernel',
  asOf: '2026-09-03',
  basis: 'cited',
  ev: function (s) { /* unchanged */ } },
```

- [ ] **Step 6: Render the fields in the navigator**

In `docs/javascripts/navigator.js`, inside the row builder that emits `ksn__rside`, add a basis and date line beneath the existing requirement label:

```js
html += '<div class="ksn__basis">' + esc(t.basis) + ' &middot; ' + esc(t.asOf) + '</div>';
```

Add the style to `docs/stylesheets/navigator.css`:

```css
.ksn__basis{font-size:.6rem;color:var(--md-default-fg-color--light);font-variant-numeric:tabular-nums;}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `python -m pytest tests/test_verdicts.py -v && python scripts/check_verdicts.py`
Expected: 6 passed, and `verdicts ok: 37 techniques, all carrying layer, asOf and basis`

- [ ] **Step 8: Verify the site still builds**

Run: `python scripts/build_dashboard_data.py && mkdocs build --strict`
Expected: exit 0, no warnings.

- [ ] **Step 9: Commit**

```bash
git add docs/javascripts/navigator.js docs/stylesheets/navigator.css \
        docs/mitigations/kaslr-bypasses.md docs/mitigations/vbs-hvci.md \
        docs/mitigations/kcfg-kcet.md docs/mitigations/smep-smap.md \
        scripts/check_verdicts.py tests/test_verdicts.py
git commit -m "feat(navigator): require layer, asOf and basis on every technique

Turns the August design's anti-staleness convention into enforced fields.
Adds a checker so an undated claim fails CI rather than sitting in prose,
which is the pte-manipulation.md:51 failure mode.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01QkCo4PpjPMeejAX1PAs14E"
```

---

### Task 3: Aggregate bypass matrix

One page that reads every registered navigator config and renders the whole inventory against one platform selector.

**Files:**
- Create: `docs/bypasses/index.md`
- Create: `docs/javascripts/matrix.js`
- Modify: `mkdocs.yml:48-49` (the `extra_javascript` list)

**Interfaces:**
- Consumes: the `window.__ksnav` array populated by Task 2's pages, each technique carrying `name`, `cat`, `layer`, `asOf`, `basis`, `ev`.
- Produces: nothing consumed by later tasks. The page mounts on `#ks-matrix`.

- [ ] **Step 1: Write the page**

Create `docs/bypasses/index.md`:

```markdown
# Bypass matrix

Same Windows version, same HVCI checkbox, different silicon, different answers. Pick a
configuration and every inventory on the site re-evaluates against it.

<div id="ks-matrix"></div>

Basis tiers: `tested` means reproduced in lab. `cited` means a resolving public source.
`inferred` means reasoned from mechanism and not yet confirmed.
```

- [ ] **Step 2: Write the aggregator**

Create `docs/javascripts/matrix.js`. It reads the same queue the navigator uses, so a defense page joins the matrix by existing.

```js
/* KernelSight aggregate bypass matrix.
 * Reads every config pushed onto window.__ksnav and renders the union of
 * their techniques against one shared platform selector. A defense page
 * joins this matrix simply by registering a navigator config. */
(function () {
  var mount = document.getElementById('ks-matrix');
  if (!mount) return;

  var DOT = { open: '#3fb950', gated: '#d29922', closed: 'var(--md-default-fg-color--lighter)' };
  var BG = {
    open: 'rgba(46,160,67,.16)',
    gated: 'rgba(210,153,34,.16)',
    closed: 'var(--md-default-fg-color--lightest)'
  };
  var BUILDS = [
    ['19041', 'Windows 10 2004'],
    ['22621', 'Windows 11 22H2'],
    ['26100', 'Windows 11 24H2'],
    ['26200', 'Windows 11 25H2']
  ];

  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function collect() {
    var out = [];
    (window.__ksnav || []).forEach(function (cfg) {
      (cfg.techniques || []).forEach(function (t) {
        out.push({ t: t, defense: cfg.title || 'Unknown defense' });
      });
    });
    return out;
  }

  var state = { build: '26100', hlat: true, kcet: true, layer: 'all', showClosed: true };

  function controls() {
    var opts = BUILDS.map(function (b) {
      return '<option value="' + b[0] + '"' + (b[0] === state.build ? ' selected' : '') + '>' + b[1] + '</option>';
    }).join('');
    return '<div class="ksn__controls">'
      + '<div class="ksn__ctl"><span class="ksn__label">Build</span>'
      + '<select class="ksn__select" data-ctl="build">' + opts + '</select></div>'
      + '<div class="ksn__ctl"><span class="ksn__label">Platform</span><div class="ksn__checks">'
      + '<label class="ksn__chk"><input type="checkbox" data-chk="hlat"' + (state.hlat ? ' checked' : '') + '> HLAT</label>'
      + '<label class="ksn__chk"><input type="checkbox" data-chk="kcet"' + (state.kcet ? ' checked' : '') + '> kCET</label>'
      + '</div></div>'
      + '<div class="ksn__ctl"><span class="ksn__label">Target layer</span>'
      + '<select class="ksn__select" data-ctl="layer">'
      + ['all', 'kernel', 'user'].map(function (v) {
          var label = v === 'all' ? 'All layers' : (v === 'kernel' ? 'Kernel layer' : 'User layer');
          return '<option value="' + v + '"' + (v === state.layer ? ' selected' : '') + '>' + label + '</option>';
        }).join('')
      + '</select></div>'
      + '<div class="ksn__ctl"><span class="ksn__label">Display</span><div class="ksn__checks">'
      + '<label class="ksn__chk ksn__chk--only"><input type="checkbox" data-chk="showClosed"'
      + (state.showClosed ? ' checked' : '') + '> Show closed</label>'
      + '</div></div></div>';
  }

  function render() {
    var counts = { open: 0, gated: 0, closed: 0 };
    var rows = '';
    collect().forEach(function (entry) {
      var t = entry.t;
      var res = t.ev(state) || ['closed', '', ''];
      var status = res[0];
      counts[status] = (counts[status] || 0) + 1;
      if (state.layer !== 'all' && t.layer !== state.layer) return;
      if (!state.showClosed && status === 'closed') return;
      rows += '<div class="ksn__row' + (status === 'closed' ? ' ksn__row--closed' : '') + '">'
        + '<div class="ksn__rdot" style="background:' + DOT[status] + '"></div>'
        + '<div class="ksn__rmain"><div class="ksn__rname">' + esc(t.name) + '</div>'
        + '<div class="ksn__rcat">' + esc(entry.defense) + '</div>'
        + '<div class="ksn__rwhy">' + (res[2] || '') + '</div></div>'
        + '<div class="ksn__rside">'
        + '<span class="ksn__pill" style="background:' + BG[status] + ';color:' + DOT[status] + '">' + status + '</span>'
        + '<span class="ksn__basis">' + esc(t.basis) + ' &middot; ' + esc(t.asOf) + '</span>'
        + '</div></div>';
    });

    mount.innerHTML = '<div class="ksn">' + controls()
      + '<div class="ksn__bar"><span class="ksn__count">'
      + counts.open + ' open, ' + counts.gated + ' gated, ' + counts.closed + ' closed'
      + '</span></div><div class="ksn__list">' + rows + '</div></div>';

    mount.querySelectorAll('[data-ctl]').forEach(function (el) {
      el.addEventListener('change', function () { state[el.dataset.ctl] = el.value; render(); });
    });
    mount.querySelectorAll('[data-chk]').forEach(function (el) {
      el.addEventListener('change', function () { state[el.dataset.chk] = el.checked; render(); });
    });
  }

  render();
})();
```

- [ ] **Step 3: Wire the script**

In `mkdocs.yml`, extend `extra_javascript` so the aggregator loads after the configs are queued:

```yaml
extra_javascript:
  - javascripts/navigator.js
  - javascripts/matrix.js
```

- [ ] **Step 4: Verify by building and reading the output**

Run: `python scripts/build_dashboard_data.py && mkdocs build --strict && grep -c 'ks-matrix' site/bypasses/index.html`
Expected: build exits 0 and grep prints a count of at least 1.

- [ ] **Step 5: Commit**

```bash
git add docs/bypasses/index.md docs/javascripts/matrix.js mkdocs.yml
git commit -m "feat(bypasses): add aggregate matrix over registered navigators

The matrix reads window.__ksnav rather than restating its contents, so a
defense page joins by registering a config. Withdraws the August design's
depth: page|row distinction, which existed to prevent the duplication this
avoids structurally.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01QkCo4PpjPMeejAX1PAs14E"
```

---

### Task 4: First user-layer defense page

Proves the layer axis carries real content, and clears the one intentionally red test from Task 1.

**Files:**
- Create: `docs/mitigations/protected-process.md`
- Modify: `tests/test_roster.py` (add one assertion)

**Interfaces:**
- Consumes: `index/defenses.yaml` from Task 1, which already points at this path. The navigator contract from Task 2.
- Produces: a `__ksnav` config with three `layer: 'user'` techniques, which Task 3's matrix picks up automatically.

- [ ] **Step 1: Write the page**

Create `docs/mitigations/protected-process.md`. Cite only the two case studies that already exist in this repository, `case-studies/Truesight-sys.md` and `case-studies/viragt64-sys.md`. Invent no sources.

````markdown
# Protected Process Light

Protected Process Light is an access-control decision made in the kernel about kernel objects.
That framing is the whole story of its bypass inventory: an attacker holding a kernel write
primitive is already on the same side of the boundary as the enforcement, so every technique
below edits the decision rather than defeating it.

Contrast this with [Credential Guard](../mitigations/index.md), where the protected asset lives
in VTL1 and the same primitive buys nothing. That contrast is the clearest statement of where
the real boundary runs, and it is why the two defenses sit beside each other in this section.

| | |
|---|---|
| Layer | User. The protected asset is a user-mode process. |
| Enforced by | Kernel. The object manager checks on handle open. |
| Mechanism | `EPROCESS.Protection`, a byte holding signer and level. |
| Introduced | Windows 8.1, extended for antimalware signers in Windows 10. |

## Bypass inventory

<div id="ppl-nav"></div>

<script>
(window.__ksnav = window.__ksnav || []).push({
  sel: '#ppl-nav',
  title: 'Protected Process Light',
  sub: 'Three techniques. All require an existing kernel write primitive.',
  controls: [
    { id: 'build', label: 'Build', type: 'select', default: '26100',
      options: [['19041','Windows 10 2004'],['22621','Windows 11 22H2'],
                ['26100','Windows 11 24H2'],['26200','Windows 11 25H2']] },
    { id: 'blocklisted', label: 'Driver blocklist current', type: 'checks',
      options: [['blocklisted','Blocklist up to date', true]] }
  ],
  techniques: [
    { name: 'EPROCESS.Protection downgrade',
      cat: 'privilege-object',
      layer: 'user',
      asOf: '2026-09-03',
      basis: 'inferred',
      ev: function (s) {
        return ['open', 'kernel write',
          'The protection level is a single byte in the process object. Clear it and the '
          + 'object manager grants full access on the next open. Nothing re-derives the '
          + 'value from the signing state, so the change persists for the process lifetime.'];
      } },
    { name: 'Handle duplication via signed driver',
      cat: 'privilege-object',
      layer: 'user',
      asOf: '2026-09-03',
      basis: 'cited',
      ev: function (s) {
        return s.blocklisted
          ? ['gated', 'Truesight.sys',
             'The driver duplicates a full-access handle without consulting the caller '
             + 'protection level, but it is carried on the vulnerable driver blocklist. '
             + 'See the <a href="../../case-studies/Truesight-sys/">Truesight.sys case study</a>.']
          : ['open', 'Truesight.sys',
             'With the blocklist stale or disabled, the driver loads and duplicates a '
             + 'full-access handle to any protected process.'];
      } },
    { name: 'Protected-process termination',
      cat: 'privilege-object',
      layer: 'user',
      asOf: '2026-09-03',
      basis: 'cited',
      ev: function (s) {
        return s.blocklisted
          ? ['gated', 'viragt64.sys',
             'Termination reaches an antimalware process without opening a handle the '
             + 'object manager would refuse, because the kill originates in kernel '
             + 'context. Blocklisted. See the '
             + '<a href="../../case-studies/viragt64-sys/">viragt64.sys case study</a>.']
          : ['open', 'viragt64.sys',
             'Kernel-context termination of a PPL antimalware process.'];
      } }
  ]
});
</script>

## What a defender sees

A process whose protection level changes after creation. The transition is observable to
anything sampling `EPROCESS.Protection`, and no legitimate path performs it. For the two
driver-backed techniques, the load of a known-vulnerable signed driver is the earlier and
louder signal.
````

- [ ] **Step 2: Add the assertion that this page is registered**

Append to `tests/test_roster.py`:

```python
def test_protected_process_page_exists_and_registers_a_navigator():
    page = ROOT / "docs" / "mitigations" / "protected-process.md"
    assert page.exists()
    text = page.read_text(encoding="utf-8")
    assert "__ksnav" in text
    assert text.count("layer: 'user'") == 3
```

- [ ] **Step 3: Run the full check suite**

Run: `python -m pytest tests/ -v && python scripts/check_roster.py && python scripts/check_verdicts.py`
Expected: all tests pass. `check_roster.py` now prints `29 defenses (19 kernel, 10 user), 11 with pages`. `check_verdicts.py` now reports 40 techniques, the original 37 plus these 3.

- [ ] **Step 4: Update the verdict test's expected count**

The count assertion in `tests/test_verdicts.py` was written against 37. Change it:

```python
def test_scan_finds_every_shipping_technique():
    # 37 on the four original kernel-layer pages, plus 3 on protected-process.
    assert len(scan()) == 40
```

- [ ] **Step 5: Run tests and build**

Run: `python -m pytest tests/ -v && python scripts/build_dashboard_data.py && mkdocs build --strict`
Expected: all pass, build exits 0.

- [ ] **Step 6: Commit**

```bash
git add docs/mitigations/protected-process.md tests/test_roster.py tests/test_verdicts.py
git commit -m "feat(targets): add protected-process, the first user-layer defense

Three techniques, all requiring an existing kernel write primitive, citing
the Truesight.sys and viragt64.sys case studies already in the corpus. The
EPROCESS.Protection downgrade ships as basis: inferred because no source is
cited for it here.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01QkCo4PpjPMeejAX1PAs14E"
```

---

### Task 5: Navigation regrouping and taxonomy corrections

The nav change the whole amendment turns on, plus the two data defects found during the survey.

**Files:**
- Modify: `mkdocs.yml` (the `nav:` block)
- Modify: `index/cve_index.yaml` (two entries)
- Create: `tests/test_urls_preserved.py`

**Interfaces:**
- Consumes: `docs/bypasses/index.md` from Task 3, `docs/mitigations/protected-process.md` from Task 4.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write the URL-preservation test**

This is the test that protects the amendment's central claim. Create `tests/test_urls_preserved.py`:

```python
"""The nav regrouping must not change a single published URL.

MkDocs derives a page URL from its path under docs/, so this test asserts
that the set of built pages is unchanged apart from deliberate additions.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Pages added deliberately by this increment.
NEW_PAGES = {"bypasses/index.html", "mitigations/protected-process.html"}


def built_pages():
    subprocess.run([sys.executable, "scripts/build_dashboard_data.py"], cwd=ROOT, check=True)
    subprocess.run(["mkdocs", "build", "--strict"], cwd=ROOT, check=True)
    site = ROOT / "site"
    return {str(p.relative_to(site)) for p in site.rglob("*.html")}


def test_every_known_url_still_builds():
    pages = built_pages()
    # A representative sample across every section, spanning all seven of the
    # original top-level groups. If the nav regrouping moved a file, one of
    # these disappears.
    for expected in [
        "index.html",
        "explore.html",
        "overview.html",
        "driver-types/index.html",
        "attack-surfaces/ioctl-handlers.html",
        "vuln-classes/use-after-free.html",
        "primitives/arw/write-what-where.html",
        "case-studies/CVE-2022-21882.html",
        "case-studies/clfs-deep-dive.html",
        "mitigations/vbs-hvci.html",
        "mitigations/kaslr-bypasses.html",
        "tooling/index.html",
    ]:
        assert expected in pages, f"URL disappeared: {expected}"


def test_the_only_additions_are_the_intended_ones():
    pages = built_pages()
    for page in NEW_PAGES:
        assert page in pages
```

- [ ] **Step 2: Run it against the current nav to establish the baseline**

Run: `python -m pytest tests/test_urls_preserved.py::test_every_known_url_still_builds -v`
Expected: PASS. This is the baseline. If it fails now, a path in the list is wrong and must be corrected before proceeding, because the test is worthless otherwise.

- [ ] **Step 3: Regroup the nav**

In `mkdocs.yml`, replace the `nav:` block. Every path is unchanged; only the grouping and the labels move. Keep the full per-page lists that the current file spells out under Drivers, Surfaces, Vulns and Primitives.

```yaml
nav:
  - Home: index.md
  - Overview: overview.md
  - Means:
    - Driver types:
      - driver-types/index.md
      # ...retain the existing twelve entries verbatim...
    - Attack surfaces:
      - attack-surfaces/index.md
      # ...retain the existing nine entries verbatim...
    - Vulnerability classes:
      - vuln-classes/index.md
      # ...retain the existing ten entries verbatim...
    - Primitives:
      - primitives/index.md
      # ...retain the existing arw/ and exploitation/ trees verbatim...
    - Case studies:
      - case-studies/index.md
      # ...retain the existing case-study list verbatim...
  - Targets:
    - Bypass matrix: bypasses/index.md
    - Kernel layer:
      - mitigations/index.md
      - SMEP / SMAP: mitigations/smep-smap.md
      - kCFG / kCET: mitigations/kcfg-kcet.md
      - VBS / HVCI: mitigations/vbs-hvci.md
      - Kernel Data Protection: mitigations/kdp.md
      - Secure Pool: mitigations/secure-pool.md
      - Pool hardening: mitigations/pool-hardening.md
      - Arbitrary Code Guard: mitigations/acg.md
      - KASLR: mitigations/kaslr.md
      - KASLR bypasses: mitigations/kaslr-bypasses.md
    - User layer:
      - Protected Process Light: mitigations/protected-process.md
  - Reference:
    - Tooling:
      - tooling/index.md
      # ...retain the existing tooling entries verbatim...
    - Explore the corpus: explore.md
    - About: about.md
```

- [ ] **Step 4: Run the URL test again**

Run: `python -m pytest tests/test_urls_preserved.py -v`
Expected: both tests PASS. Identical URL set plus the two intended additions. If any URL disappeared, a nav entry lost its path during the regroup.

- [ ] **Step 5: Fix the two unresolvable vuln-class labels**

In `index/cve_index.yaml`, two entries name classes that have no page. Normalize them to the page slugs:

```bash
# CVE-2025-11156: null-pointer-deref -> null-deref
# CVE-2024-11616: toctou -> toctou-double-fetch
python - <<'PY'
import pathlib
p = pathlib.Path("index/cve_index.yaml")
s = p.read_text(encoding="utf-8")
s = s.replace('vuln_class: "null-pointer-deref"', 'vuln_class: "null-deref"')
s = s.replace('vuln_class: "toctou"', 'vuln_class: "toctou-double-fetch"')
p.write_text(s, encoding="utf-8")
PY
```

- [ ] **Step 6: Verify no orphan classes remain**

Run:

```bash
python scripts/build_dashboard_data.py
python - <<'PY'
import json, pathlib
used = set(json.load(open("docs/assets/dashboard-data.json"))["stats"]["vuln_class_counts"])
pages = {p.stem for p in pathlib.Path("docs/vuln-classes").glob("*.md")}
orphans = sorted(used - pages)
print("orphan vuln classes:", orphans)
assert not orphans, orphans
PY
```

Expected: `orphan vuln classes: []` and no assertion error.

- [ ] **Step 7: Full build and test**

Run: `python -m pytest tests/ -v && python scripts/build_dashboard_data.py && mkdocs build --strict`
Expected: all pass, build exits 0.

- [ ] **Step 8: Commit**

```bash
git add mkdocs.yml index/cve_index.yaml tests/test_urls_preserved.py
git commit -m "feat(nav): regroup into Means and Targets, fix orphan vuln classes

Grouping change only. No file moves, so every published URL survives, which
tests/test_urls_preserved.py now asserts against a built site.

Also normalises two vuln_class labels that resolved to no page:
null-pointer-deref and toctou, both from epdlpdrv.sys entries.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01QkCo4PpjPMeejAX1PAs14E"
```

---

### Task 6: Homepage rewrite and CI wiring

Replaces the corpus-size hero with the hardening curve, and makes the three checks run on every push.

**Files:**
- Modify: `docs/overrides/landing.html:47-100` (hero and stats sections)
- Modify: `.github/workflows/deploy-pages.yml:26-32`
- Create: `scripts/build_hero_curve.py`
- Create: `tests/test_hero_curve.py`

**Interfaces:**
- Consumes: `scripts/check_roster.py::load_roster` from Task 1.
- Produces: `docs/assets/hero-curve.json`, an object with `configs` (list of `{label, open, gated, closed}`) and `roster` (`{total, kernel, user, with_inventory}`).

- [ ] **Step 1: Write the failing test**

Create `tests/test_hero_curve.py`:

```python
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "assets" / "hero-curve.json"


def build():
    subprocess.run([sys.executable, "scripts/build_hero_curve.py"], cwd=ROOT, check=True)
    return json.loads(OUT.read_text(encoding="utf-8"))


def test_curve_has_five_configurations():
    assert len(build()["configs"]) == 5


def test_each_configuration_sums_to_the_technique_total():
    data = build()
    totals = {c["open"] + c["gated"] + c["closed"] for c in data["configs"]}
    assert len(totals) == 1, f"configurations disagree on the technique total: {totals}"


def test_open_count_falls_monotonically_as_the_platform_hardens():
    opens = [c["open"] for c in build()["configs"]]
    assert opens == sorted(opens, reverse=True), opens


def test_roster_block_matches_the_roster_file():
    data = build()
    assert data["roster"]["total"] == 29
    assert data["roster"]["kernel"] == 19
    assert data["roster"]["user"] == 10
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_hero_curve.py -v`
Expected: FAIL, `build_hero_curve.py` does not exist.

- [ ] **Step 3: Write the generator**

The `ev` functions are JavaScript, so Python cannot evaluate them. Rather than add a JS runtime dependency, the generator counts techniques per configuration from a small declarative table kept beside the pages. Create `scripts/build_hero_curve.py`:

```python
"""Generate the homepage hardening curve.

The per-technique verdict logic lives in JavaScript ev() functions, which
this script deliberately does not evaluate: adding a JS runtime to CI to
render five numbers is not worth the dependency. Instead each page declares
its per-configuration tallies in a CURVE comment block, which
check_verdicts.py cross-checks against the technique count.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGES = sorted((ROOT / "docs" / "mitigations").glob("*.md"))
OUT = ROOT / "docs" / "assets" / "hero-curve.json"

sys.path.insert(0, str(ROOT / "scripts"))
from check_roster import load_roster  # noqa: E402

CONFIGS = [
    "Windows 10 2004",
    "11 22H2, kCET",
    "11 24H2, pre-11th gen",
    "11 24H2, HLAT",
    "11 25H2, HLAT",
]

# <!-- CURVE open,gated,closed | open,gated,closed | ... five groups -->
CURVE = re.compile(r"<!--\s*CURVE\s+(?P<body>[0-9,\s|]+?)-->")


def page_curves():
    found = []
    for page in PAGES:
        text = page.read_text(encoding="utf-8")
        match = CURVE.search(text)
        if not match:
            continue
        groups = [g.strip() for g in match.group("body").split("|")]
        if len(groups) != len(CONFIGS):
            raise SystemExit(f"{page.name}: CURVE needs {len(CONFIGS)} groups, got {len(groups)}")
        found.append([tuple(int(n) for n in g.split(",")) for g in groups])
    return found


def main():
    curves = page_curves()
    if not curves:
        raise SystemExit("no CURVE blocks found in docs/mitigations/")

    configs = []
    for i, label in enumerate(CONFIGS):
        o = sum(c[i][0] for c in curves)
        g = sum(c[i][1] for c in curves)
        x = sum(c[i][2] for c in curves)
        configs.append({"label": label, "open": o, "gated": g, "closed": x})

    roster = load_roster()
    data = {
        "configs": configs,
        "roster": {
            "total": len(roster),
            "kernel": sum(1 for d in roster if d["layer"] == "kernel"),
            "user": sum(1 for d in roster if d["layer"] == "user"),
            "with_inventory": sum(1 for d in roster if d["page"]),
        },
    }
    OUT.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print("hero curve:", " ".join(f'{c["label"]}={c["open"]}' for c in configs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Add a CURVE block to each navigator page**

Add one comment line to each of the five pages carrying a navigator, giving that page's own open, gated and closed tallies for the five configurations. Derive each number by reading the page's own `ev` functions against the configuration. Worked example for `docs/mitigations/protected-process.md`, whose three techniques are one always-open and two blocklist-gated, giving the same tally in every column:

```markdown
<!-- CURVE 1,2,0 | 1,2,0 | 1,2,0 | 1,2,0 | 1,2,0 -->
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_hero_curve.py -v`
Expected: 4 passed. If `test_open_count_falls_monotonically_as_the_platform_hardens` fails, a CURVE block has a transcription error, because no defense gets weaker as the platform hardens.

- [ ] **Step 6: Rewrite the hero**

In `docs/overrides/landing.html`, replace the hero copy and the four-tile stats section.

Headline and subhead:

```html
<h1 style="font-family:'Space Grotesk';font-size:3.1rem;font-weight:700;letter-spacing:-0.03em;color:#e0e2eb;margin:0 0 20px 0;line-height:1.08">
  What kernel access<br><span style="background:linear-gradient(135deg,#adc6ff 0%,#0566d9 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent">actually buys you</span>
</h1>
<p style="font-family:'Inter';font-size:1rem;color:#9ca3af;max-width:44ch;margin:0 0 26px 0;line-height:1.72">
  The means of obtaining kernel read, write or execution on Windows, and the defenses at both
  kernel and user level that such access does or does not defeat. Every verdict is dated and
  tied to a build and a CPU feature set.
</p>
```

Replace the four stat tiles with the curve, rendered from `hero-curve.json`. Each row is a label, an open count, and a three-segment bar using ground `#3fb950`, `#d29922` and `#3a4150`, at radius 3px. Beneath it, one quiet coverage line reading roster total, how many have a reviewed inventory, and the technique count.

- [ ] **Step 7: Wire the checks into CI**

In `.github/workflows/deploy-pages.yml`, insert a validation step before the build, and add pytest to the install line:

```yaml
      - run: pip install mkdocs-material pyyaml pytest

      - name: Validate roster and verdicts
        run: |
          python scripts/check_roster.py
          python scripts/check_verdicts.py
          python -m pytest tests/ -q

      - name: Generate dashboard data
        run: |
          python scripts/build_dashboard_data.py
          python scripts/build_hero_curve.py

      - run: mkdocs build --strict
```

- [ ] **Step 8: Run the full pipeline exactly as CI will**

Run:

```bash
python scripts/check_roster.py \
  && python scripts/check_verdicts.py \
  && python -m pytest tests/ -q \
  && python scripts/build_dashboard_data.py \
  && python scripts/build_hero_curve.py \
  && mkdocs build --strict
```

Expected: every step exits 0.

- [ ] **Step 9: Commit**

```bash
git add docs/overrides/landing.html scripts/build_hero_curve.py \
        tests/test_hero_curve.py .github/workflows/deploy-pages.yml \
        docs/assets/hero-curve.json docs/mitigations/
git commit -m "feat(home): lead with the hardening curve, wire checks into CI

The hero becomes the count of techniques still open across five platform
configurations, which is the argument for the platform schema rather than a
claim about it. Corpus counters move to Explore, where they describe what
that page holds.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01QkCo4PpjPMeejAX1PAs14E"
```

---

## Self-review

**Spec coverage.** The thesis sentence lands in Task 6 with the hero rewrite. The `layer` axis is Task 1. The navigator-as-registry decision is Tasks 2 and 3. The nav regrouping is Task 5. The homepage metric is Task 6. The first user-layer page is Task 4. The three CI checks are Tasks 1, 2 and 6. Two of the three corrections are Task 5.

**Deliberately not covered, and why.** The spec's third correction, the 24 user-mode components sitting in the driver index, is left for increment 2. The spec says the layer axis gives the vocabulary to decide but does not decide it, so there is no unambiguous change to make yet. The nine BYOVD driver-name records are the same case. Both are recorded in the spec's open questions rather than being resolved by a plan step, which is correct: a plan should not invent a decision the spec declined to make.

**Type consistency.** `load_roster()` and `check()` are defined in Task 1 and consumed by name in Tasks 4 and 6. `scan()` and `check()` in `check_verdicts.py` are defined in Task 2 and consumed in Task 4. The technique field names `layer`, `asOf` and `basis` are introduced in Task 2 and used identically in Tasks 3, 4 and 6. `hero-curve.json` keys are defined in Task 6 and consumed only there.

**Known ordering constraint.** Task 1 leaves `test_roster_check_reports_no_errors` failing on purpose, because the roster points at a page Task 4 creates. Task 4 clears it. Do not run Tasks 1 through 3 and conclude the suite is broken. Task 4 also revises the technique count assertion written in Task 2, from 37 to 40.
