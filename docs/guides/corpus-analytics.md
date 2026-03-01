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

## Kernel CVE Volume by Year

Windows kernel-mode components average 90--140 CVEs per year. The chart below counts every CVE in the NVD whose description mentions a kernel-mode component -- ntoskrnl, win32k, CLFS, AFD, NTFS, TCP/IP, DWM, cloud files mini-filter, or kernel-mode driver.

<div class="ks-figure" markdown>
  <span class="ks-figure-label">FIG — Windows Kernel-Mode CVEs by Year (NVD)</span>
  <svg viewBox="0 0 700 270" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Bar chart showing Windows kernel-mode CVE counts from NVD by year, 2015 to 2026">
    <!-- Y-axis -->
    <text class="ks-annotation" x="55" y="213" text-anchor="end">0</text>
    <line class="ks-line" x1="60" y1="210" x2="660" y2="210" opacity="0.15"/>
    <text class="ks-annotation" x="55" y="163" text-anchor="end">50</text>
    <line class="ks-line" x1="60" y1="160" x2="660" y2="160" opacity="0.15"/>
    <text class="ks-annotation" x="55" y="113" text-anchor="end">100</text>
    <line class="ks-line" x1="60" y1="110" x2="660" y2="110" opacity="0.15"/>
    <text class="ks-annotation" x="55" y="63" text-anchor="end">150</text>
    <line class="ks-line" x1="60" y1="60" x2="660" y2="60" opacity="0.15"/>
    <!-- 2015 -->
    <rect class="ks-box" x="65" y="144" width="35" height="66" rx="0"/>
    <text class="ks-annotation" x="82" y="140">66</text>
    <text class="ks-annotation" x="82" y="228" text-anchor="middle">2015</text>
    <!-- 2016 -->
    <rect class="ks-box" x="115" y="112" width="35" height="98" rx="0"/>
    <text class="ks-annotation" x="132" y="108">98</text>
    <text class="ks-annotation" x="132" y="228" text-anchor="middle">2016</text>
    <!-- 2017 -->
    <rect class="ks-box" x="165" y="71" width="35" height="139" rx="0"/>
    <text class="ks-annotation" x="182" y="67">139</text>
    <text class="ks-annotation" x="182" y="228" text-anchor="middle">2017</text>
    <!-- 2018 -->
    <rect class="ks-box" x="215" y="87" width="35" height="123" rx="0"/>
    <text class="ks-annotation" x="232" y="83">123</text>
    <text class="ks-annotation" x="232" y="228" text-anchor="middle">2018</text>
    <!-- 2019 -->
    <rect class="ks-box" x="265" y="119" width="35" height="91" rx="0"/>
    <text class="ks-annotation" x="282" y="115">91</text>
    <text class="ks-annotation" x="282" y="228" text-anchor="middle">2019</text>
    <!-- 2020 -->
    <rect class="ks-box" x="315" y="89" width="35" height="121" rx="0"/>
    <text class="ks-annotation" x="332" y="85">121</text>
    <text class="ks-annotation" x="332" y="228" text-anchor="middle">2020</text>
    <!-- 2021 -->
    <rect class="ks-box" x="365" y="119" width="35" height="91" rx="0"/>
    <text class="ks-annotation" x="382" y="115">91</text>
    <text class="ks-annotation" x="382" y="228" text-anchor="middle">2021</text>
    <!-- 2022 -->
    <rect class="ks-box" x="415" y="118" width="35" height="92" rx="0"/>
    <text class="ks-annotation" x="432" y="114">92</text>
    <text class="ks-annotation" x="432" y="228" text-anchor="middle">2022</text>
    <!-- 2023 -->
    <rect class="ks-box" x="465" y="105" width="35" height="105" rx="0"/>
    <text class="ks-annotation" x="482" y="101">105</text>
    <text class="ks-annotation" x="482" y="228" text-anchor="middle">2023</text>
    <!-- 2024 -->
    <rect class="ks-box" x="515" y="100" width="35" height="110" rx="0"/>
    <text class="ks-annotation" x="532" y="96">110</text>
    <text class="ks-annotation" x="532" y="228" text-anchor="middle">2024</text>
    <!-- 2025 -->
    <rect class="ks-box" x="565" y="81" width="35" height="129" rx="0"/>
    <text class="ks-annotation" x="582" y="77">129</text>
    <text class="ks-annotation" x="582" y="228" text-anchor="middle">2025</text>
    <!-- 2026 (partial) -->
    <rect class="ks-box" x="615" y="183" width="35" height="27" rx="0" opacity="0.5"/>
    <text class="ks-annotation" x="632" y="179">27</text>
    <text class="ks-annotation" x="632" y="228" text-anchor="middle">2026*</text>
  </svg>
  <p class="ks-figure-caption">Counts from NVD keyword search across kernel-mode component descriptions. 2017's spike coincides with Microsoft's switch from security bulletins to per-CVE advisories. 2026* is partial (Jan--Feb only).</p>
</div>

Annual volume stays between 90 and 140 with no clear upward trend since 2017. The swings mostly track advisory timing rather than actual changes in the kernel's attack surface. Microsoft's 2017 shift from monthly bulletins to individual CVE IDs pushed that year's count up artificially. The 2019 and 2021 dips coincide with lighter Patch Tuesday months, not fewer vulnerabilities.

### Corpus Coverage

The KernelSight corpus samples 147 of roughly 1,200 kernel-mode CVEs disclosed since 2015 -- about 12%. The sampling is deliberate: the corpus tracks CVEs that have published exploit research, not a random cross-section of Patch Tuesday fixes.

| Period | NVD Total | Corpus | Coverage |
|--------|-----------|--------|----------|
| 2015--2021 | 689 | 12 | 1.7% |
| 2022 | 92 | 9 | 9.8% |
| 2023 | 105 | 17 | 16.2% |
| 2024 | 110 | 23 | 20.9% |
| 2025 | 129 | 72 | 55.8% |
| 2026 (partial) | 27 | 14 | 51.9% |

Coverage concentrates on 2025--2026 because those years have the most public exploit writeups. The 2022--2024 jump reflects backfilling CVEs with published exploit research (CLFS ransomware chain, Project Zero registry audit, DEVCORE kernel streaming work). Most pre-2022 entries are BYOVD drivers where the vulnerability existed years before formal CVE assignment.

## Vulnerability Class Breakdown

Buffer overflows are most common, followed closely by use-after-free, which dominates the exploited-in-the-wild cases. BYOVD drivers account for most "Arbitrary R/W" entries -- intentional design choices rather than bugs.

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
