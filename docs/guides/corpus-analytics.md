# Corpus Analytics

> Visual breakdown of 134 CVEs across 62 drivers -- what gets exploited, how often, and where the patterns cluster.

## CVEs by Driver Family

The top 10 driver families account for roughly 75% of the corpus. Four families -- afd.sys, clfs.sys, win32k, and the Kernel Streaming stack -- share the lead at 12--13 CVEs each.

<div class="ks-figure" markdown>
  <span class="ks-figure-label">FIG — CVEs by Driver Family (Top 10)</span>
  <svg viewBox="0 0 700 340" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Horizontal bar chart showing CVE counts by driver family">
    <!-- afd.sys -->
    <text class="ks-label" x="175" y="35" text-anchor="end">afd.sys</text>
    <rect class="ks-box" x="180" y="22" width="338" height="20" rx="0"/>
    <text class="ks-annotation" x="526" y="36">13</text>
    <!-- clfs.sys -->
    <text class="ks-label" x="175" y="65" text-anchor="end">clfs.sys</text>
    <rect class="ks-box" x="180" y="52" width="312" height="20" rx="0"/>
    <text class="ks-annotation" x="500" y="66">12</text>
    <!-- win32k family -->
    <text class="ks-label" x="175" y="95" text-anchor="end">win32k family</text>
    <rect class="ks-box" x="180" y="82" width="312" height="20" rx="0"/>
    <text class="ks-annotation" x="500" y="96">12</text>
    <!-- Kernel Streaming -->
    <text class="ks-label" x="175" y="125" text-anchor="end">KS stack</text>
    <rect class="ks-box" x="180" y="112" width="312" height="20" rx="0"/>
    <text class="ks-annotation" x="500" y="126">12</text>
    <!-- ntoskrnl -->
    <text class="ks-label" x="175" y="155" text-anchor="end">ntoskrnl.exe</text>
    <rect class="ks-box" x="180" y="142" width="234" height="20" rx="0"/>
    <text class="ks-annotation" x="422" y="156">9</text>
    <!-- dwmcore.dll -->
    <text class="ks-label" x="175" y="185" text-anchor="end">dwmcore.dll</text>
    <rect class="ks-box" x="180" y="172" width="208" height="20" rx="0"/>
    <text class="ks-annotation" x="396" y="186">8</text>
    <!-- cldflt.sys -->
    <text class="ks-label" x="175" y="215" text-anchor="end">cldflt.sys</text>
    <rect class="ks-box" x="180" y="202" width="208" height="20" rx="0"/>
    <text class="ks-annotation" x="396" y="216">8</text>
    <!-- ntfs.sys -->
    <text class="ks-label" x="175" y="245" text-anchor="end">ntfs.sys</text>
    <rect class="ks-box" x="180" y="232" width="182" height="20" rx="0"/>
    <text class="ks-annotation" x="370" y="246">7</text>
    <!-- BioNTdrv.sys -->
    <text class="ks-label" x="175" y="275" text-anchor="end">BioNTdrv.sys</text>
    <rect class="ks-box" x="180" y="262" width="130" height="20" rx="0"/>
    <text class="ks-annotation" x="318" y="276">5</text>
    <!-- epdlpdrv.sys -->
    <text class="ks-label" x="175" y="305" text-anchor="end">epdlpdrv.sys</text>
    <rect class="ks-box" x="180" y="292" width="78" height="20" rx="0"/>
    <text class="ks-annotation" x="266" y="306">3</text>
  </svg>
  <p class="ks-figure-caption">"win32k family" combines win32k.sys, win32kbase.sys, and win32kfull.sys. "KS stack" combines ks.sys, ksthunk.sys, and mskssrv.sys. Remaining 44 CVEs span 52 additional drivers.</p>
</div>

## CVEs by Year

Most CVEs land in 2025, partly because Patch Tuesday coverage expanded and more researchers started poking at kernel attack surface. The year reflects disclosure, not discovery.

<div class="ks-figure" markdown>
  <span class="ks-figure-label">FIG — CVEs by Disclosure Year</span>
  <svg viewBox="0 0 700 260" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Stacked bar chart showing CVE counts by year, split between ITW and non-ITW">
    <!-- Y-axis labels -->
    <text class="ks-annotation" x="40" y="210" text-anchor="end">0</text>
    <line class="ks-line" x1="45" y1="207" x2="670" y2="207" opacity="0.15"/>
    <text class="ks-annotation" x="40" y="170" text-anchor="end">20</text>
    <line class="ks-line" x1="45" y1="167" x2="670" y2="167" opacity="0.15"/>
    <text class="ks-annotation" x="40" y="130" text-anchor="end">40</text>
    <line class="ks-line" x1="45" y1="127" x2="670" y2="127" opacity="0.15"/>
    <text class="ks-annotation" x="40" y="90" text-anchor="end">60</text>
    <line class="ks-line" x1="45" y1="87" x2="670" y2="87" opacity="0.15"/>
    <text class="ks-annotation" x="40" y="50" text-anchor="end">80</text>
    <line class="ks-line" x1="45" y1="47" x2="670" y2="47" opacity="0.15"/>
    <!-- 2015-2021 (12 total, 5 ITW) -->
    <rect class="ks-box" x="65" y="183" width="40" height="24" rx="0"/>
    <rect class="ks-box" x="65" y="173" width="40" height="10" rx="0" opacity="0.5"/>
    <text class="ks-annotation" x="85" y="170">12</text>
    <text class="ks-annotation" x="85" y="225" text-anchor="middle">&#x2264;21</text>
    <!-- 2022 (4 total, 3 ITW) -->
    <rect class="ks-box" x="130" y="205" width="40" height="2" rx="0"/>
    <rect class="ks-box" x="130" y="199" width="40" height="6" rx="0" opacity="0.5"/>
    <text class="ks-annotation" x="150" y="196">4</text>
    <text class="ks-annotation" x="150" y="225" text-anchor="middle">2022</text>
    <!-- 2023 (14 total, 5 ITW) -->
    <rect class="ks-box" x="195" y="189" width="40" height="18" rx="0"/>
    <rect class="ks-box" x="195" y="179" width="40" height="10" rx="0" opacity="0.5"/>
    <text class="ks-annotation" x="215" y="176">14</text>
    <text class="ks-annotation" x="215" y="225" text-anchor="middle">2023</text>
    <!-- 2024 (18 total, 7 ITW) -->
    <rect class="ks-box" x="260" y="185" width="40" height="22" rx="0"/>
    <rect class="ks-box" x="260" y="171" width="40" height="14" rx="0" opacity="0.5"/>
    <text class="ks-annotation" x="280" y="168">18</text>
    <text class="ks-annotation" x="280" y="225" text-anchor="middle">2024</text>
    <!-- 2025 (72 total, 27 ITW) -->
    <rect class="ks-box" x="325" y="117" width="40" height="90" rx="0"/>
    <rect class="ks-box" x="325" y="63" width="40" height="54" rx="0" opacity="0.5"/>
    <text class="ks-annotation" x="345" y="60">72</text>
    <text class="ks-annotation" x="345" y="225" text-anchor="middle">2025</text>
    <!-- 2026 (14 total, 5 ITW) -->
    <rect class="ks-box" x="390" y="189" width="40" height="18" rx="0"/>
    <rect class="ks-box" x="390" y="179" width="40" height="10" rx="0" opacity="0.5"/>
    <text class="ks-annotation" x="410" y="176">14</text>
    <text class="ks-annotation" x="410" y="225" text-anchor="middle">2026</text>
    <!-- Legend -->
    <rect class="ks-box" x="490" y="60" width="12" height="12" rx="0"/>
    <text class="ks-annotation" x="508" y="70">Non-ITW</text>
    <rect class="ks-box" x="490" y="80" width="12" height="12" rx="0" opacity="0.5"/>
    <text class="ks-annotation" x="508" y="90">Exploited ITW</text>
  </svg>
  <p class="ks-figure-caption">"&#x2264;21" combines 2015--2021 (mostly BYOVD drivers). Darker bars = not exploited in the wild; lighter bars = exploited ITW. 9 undated BYOVD entries excluded.</p>
</div>

## Vulnerability Class Breakdown

Buffer overflows lead, but use-after-free is close behind and accounts for most of the exploited-in-the-wild entries. BYOVD drivers make up most of the "Arbitrary R/W" column -- bugs by design, not accident.

<div class="ks-figure" markdown>
  <span class="ks-figure-label">FIG — Vulnerability Class Distribution</span>
  <svg viewBox="0 0 700 340" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Horizontal bar chart showing vulnerability class distribution">
    <!-- Buffer Overflow -->
    <text class="ks-label" x="175" y="35" text-anchor="end">Buffer Overflow</text>
    <rect class="ks-box" x="180" y="22" width="240" height="20" rx="0"/>
    <text class="ks-annotation" x="428" y="36">30</text>
    <!-- Use-After-Free -->
    <text class="ks-label" x="175" y="65" text-anchor="end">Use-After-Free</text>
    <rect class="ks-box" x="180" y="52" width="200" height="20" rx="0"/>
    <text class="ks-annotation" x="388" y="66">25</text>
    <!-- Arbitrary R/W -->
    <text class="ks-label" x="175" y="95" text-anchor="end">Arbitrary R/W</text>
    <rect class="ks-box" x="180" y="82" width="168" height="20" rx="0"/>
    <text class="ks-annotation" x="356" y="96">21</text>
    <!-- EoP (generic) -->
    <text class="ks-label" x="175" y="125" text-anchor="end">EoP (generic)</text>
    <rect class="ks-box" x="180" y="112" width="144" height="20" rx="0"/>
    <text class="ks-annotation" x="332" y="126">18</text>
    <!-- Race Condition -->
    <text class="ks-label" x="175" y="155" text-anchor="end">Race Condition</text>
    <rect class="ks-box" x="180" y="142" width="96" height="20" rx="0"/>
    <text class="ks-annotation" x="284" y="156">12</text>
    <!-- Info Disclosure -->
    <text class="ks-label" x="175" y="185" text-anchor="end">Info Disclosure</text>
    <rect class="ks-box" x="180" y="172" width="64" height="20" rx="0"/>
    <text class="ks-annotation" x="252" y="186">8</text>
    <!-- Type Confusion -->
    <text class="ks-label" x="175" y="215" text-anchor="end">Type Confusion</text>
    <rect class="ks-box" x="180" y="202" width="40" height="20" rx="0"/>
    <text class="ks-annotation" x="228" y="216">5</text>
    <!-- Integer Overflow -->
    <text class="ks-label" x="175" y="245" text-anchor="end">Integer Overflow</text>
    <rect class="ks-box" x="180" y="232" width="32" height="20" rx="0"/>
    <text class="ks-annotation" x="220" y="246">4</text>
    <!-- Logic Bug -->
    <text class="ks-label" x="175" y="275" text-anchor="end">Logic / Other</text>
    <rect class="ks-box" x="180" y="262" width="56" height="20" rx="0"/>
    <text class="ks-annotation" x="244" y="276">7</text>
    <!-- Process Termination -->
    <text class="ks-label" x="175" y="305" text-anchor="end">Process Kill</text>
    <rect class="ks-box" x="180" y="292" width="32" height="20" rx="0"/>
    <text class="ks-annotation" x="220" y="306">4</text>
  </svg>
  <p class="ks-figure-caption">"EoP (generic)" covers cases where the advisory doesn't specify a memory corruption class. "Process Kill" is the EDR-bypass primitive found in BYOVD anti-cheat and security product drivers.</p>
</div>

## Exploitation Status

<div class="ks-stats-box" markdown>
<span class="ks-stat-num">52</span> exploited in the wild &nbsp;&middot;&nbsp;
<span class="ks-stat-num">82</span> not exploited ITW<br>
<span class="ks-stat-num">2</span> remotely exploitable &nbsp;&middot;&nbsp;
<span class="ks-stat-num">132</span> local only<br>
<span class="ks-stat-num">41</span> third-party BYOVD drivers &nbsp;&middot;&nbsp;
<span class="ks-stat-num">93</span> Microsoft inbox drivers
</div>

Nearly 39% of the corpus has been exploited in the wild. The two remote CVEs are [CVE-2022-21907](../case-studies/CVE-2022-21907.md) (http.sys) and [CVE-2024-38063](../case-studies/CVE-2024-38063.md) (tcpip.sys). Everything else requires local access or a BYOVD drop.

BYOVD drivers are over-represented in the ITW column -- they give attackers kernel R/W without any memory corruption. See [BYOVD](../reference/byovd.md) for the full pattern.

## Driver x Vulnerability Class Heatmap

Where do specific bug types concentrate? This table crosses the top 8 driver families against the most common vulnerability classes.

| Driver | Buf Ovf | UAF | Race | Type Conf | Info Disc | Arb R/W | Int Ovf | Other |
|--------|---------|-----|------|-----------|-----------|---------|---------|-------|
| **afd.sys** | 1 | 7 | 3 | | | | 1 | 1 |
| **clfs.sys** | 7 | 2 | | | | | | 3 |
| **win32k** | | 5 | 3 | 2 | 1 | | | 1 |
| **KS stack** | 4 | 2 | | 1 | | | 1 | 4 |
| **ntoskrnl** | | 1 | 3 | | 2 | | 1 | 2 |
| **dwmcore** | 2 | 1 | | 1 | | | | 4 |
| **cldflt** | 3 | 2 | 1 | | | | | 2 |
| **ntfs** | 3 | | | | 3 | | | 1 |

Notable clusters:

- **afd.sys skews UAF.** Socket teardown races account for 7 of 13 CVEs.
- **clfs.sys skews buffer overflow.** Corrupt on-disk offsets cause OOB writes in the BLF parser.
- **win32k splits between UAF and races.** Callback reentrancy and concurrent window ops feed both.
- **ntfs.sys splits between buffer overflow and info disclosure.** Crafted VHD images hit both through MFT parsing.
- **ntoskrnl.exe leans toward races.** Token and secure-mode operations lack proper locking.

## Cross-References

- [Case Studies](../case-studies/index.md) -- full walkthroughs of individual CVEs
- [Vulnerability Classes](../vuln-classes/index.md) -- taxonomy of the underlying bug types
- [Exploit Chain Patterns](exploit-chain-patterns.md) -- how these bugs become SYSTEM
- [BYOVD](../reference/byovd.md) -- third-party driver exploitation pattern
