# KASLR Bypasses

KASLR gives the kernel 8 bits of entropy. That sounds like a barrier, but in practice it is the most routinely defeated mitigation in the Windows kernel. The 256 possible kernel base addresses can be resolved through API calls, security descriptor corruption, driver-specific info leaks, or hardware timing channels. This page catalogs every known technique, organized by the access level required and the Windows version where each was viable.

Understanding which bypass vectors remain open on a given build is essential for evaluating any kernel exploit chain. An exploit that requires a KASLR bypass is only as constrained as the cheapest available leak on the target system.

<div class="ksn" markdown="0">
<div class="ksn__head">
  <div class="ksn__title">Bypass Navigator</div>
  <div class="ksn__sub">Set your situation. The matrix marks each KASLR bypass <b>open</b>, <b>gated</b>, or <b>closed</b> for that exact target. Every row links to the detail below.</div>
</div>

<div class="ksn__controls">
  <div class="ksn__ctl">
    <label class="ksn__label" for="ksn-build">Target build</label>
    <select id="ksn-build" class="ksn__select">
      <option value="1">&le; 19H2 (legacy)</option>
      <option value="2">20H1 &ndash; 20H2</option>
      <option value="3">21H1 &ndash; 21H2</option>
      <option value="4">22H2</option>
      <option value="5">23H2</option>
      <option value="6" selected>24H2 / 25H2</option>
    </select>
  </div>
  <div class="ksn__ctl">
    <label class="ksn__label" for="ksn-il">Your access</label>
    <select id="ksn-il" class="ksn__select">
      <option value="low" selected>Low IL (sandboxed)</option>
      <option value="medium">Medium IL (standard user)</option>
    </select>
  </div>
  <div class="ksn__ctl">
    <label class="ksn__label" for="ksn-cpu">CPU</label>
    <select id="ksn-cpu" class="ksn__select">
      <option value="any" selected>Any</option>
      <option value="intel">Intel</option>
      <option value="amd">AMD</option>
    </select>
  </div>
  <div class="ksn__ctl ksn__ctl--prims">
    <span class="ksn__label">Primitives you hold</span>
    <div class="ksn__prims">
      <label class="ksn__chk"><input type="checkbox" id="ksn-write"> arbitrary write</label>
      <label class="ksn__chk"><input type="checkbox" id="ksn-bitflip"> bit-flip / partial write</label>
    </div>
  </div>
</div>

<div class="ksn__bar">
  <label class="ksn__chk ksn__chk--only"><input type="checkbox" id="ksn-only"> Show only what's open</label>
  <span class="ksn__count" id="ksn-count"></span>
</div>

<div class="ksn__list" id="ksn-list"></div>

<div class="ksn__legend">
  <span><i class="ksn__dot ksn__dot--open"></i>Open &mdash; usable as-is</span>
  <span><i class="ksn__dot ksn__dot--gated"></i>Gated &mdash; needs more access or a primitive</span>
  <span><i class="ksn__dot ksn__dot--closed"></i>Closed &mdash; patched or restricted on this build</span>
</div>
</div>

<style>
.ksn{border:1px solid var(--md-default-fg-color--lightest);border-radius:10px;padding:20px 20px 16px;margin:1.2rem 0 2rem;background:var(--md-code-bg-color);}
.ksn__title{font-size:1.15rem;font-weight:700;letter-spacing:-.01em;}
.ksn__sub{font-size:.78rem;color:var(--md-default-fg-color--light);margin-top:4px;max-width:66ch;line-height:1.5;}
.ksn__controls{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-top:18px;}
.ksn__ctl{display:flex;flex-direction:column;gap:6px;}
.ksn__ctl--prims{grid-column:1/-1;}
.ksn__label{font-size:.62rem;text-transform:uppercase;letter-spacing:.09em;color:var(--md-default-fg-color--light);font-weight:600;}
.ksn__select{font:inherit;font-size:.8rem;padding:7px 10px;border:1px solid var(--md-default-fg-color--lighter);border-radius:6px;background:var(--md-default-bg-color);color:var(--md-default-fg-color);cursor:pointer;}
.ksn__select:focus{outline:2px solid var(--md-accent-fg-color);outline-offset:1px;}
.ksn__prims{display:flex;flex-wrap:wrap;gap:8px;}
.ksn__chk{display:inline-flex;align-items:center;gap:7px;font-size:.78rem;padding:6px 12px;border:1px solid var(--md-default-fg-color--lighter);border-radius:20px;cursor:pointer;user-select:none;}
.ksn__chk input{accent-color:var(--md-accent-fg-color);}
.ksn__bar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:18px 0 10px;flex-wrap:wrap;}
.ksn__chk--only{border-radius:6px;}
.ksn__count{font-size:.72rem;color:var(--md-default-fg-color--light);font-variant-numeric:tabular-nums;}
.ksn__list{display:flex;flex-direction:column;gap:8px;}
.ksn__row{display:grid;grid-template-columns:14px 1fr auto;gap:12px;align-items:start;padding:12px 14px;border:1px solid var(--md-default-fg-color--lightest);border-radius:8px;background:var(--md-default-bg-color);}
.ksn__row--closed{opacity:.55;}
.ksn__rdot{width:9px;height:9px;border-radius:50%;margin-top:6px;}
.ksn__rmain{min-width:0;}
.ksn__rname{font-weight:650;font-size:.9rem;line-height:1.3;}
.ksn__rcat{font-size:.6rem;text-transform:uppercase;letter-spacing:.08em;color:var(--md-default-fg-color--light);margin-top:2px;}
.ksn__rwhy{font-size:.8rem;color:var(--md-default-fg-color--light);margin-top:6px;line-height:1.5;}
.ksn__rwhy a{color:var(--md-accent-fg-color);}
.ksn__rside{display:flex;flex-direction:column;align-items:flex-end;gap:6px;white-space:nowrap;}
.ksn__pill{font-size:.62rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;padding:3px 9px;border-radius:20px;}
.ksn__pill--open{background:rgba(46,160,67,.16);color:#3fb950;}
.ksn__pill--gated{background:rgba(210,153,34,.16);color:#d29922;}
.ksn__pill--closed{background:var(--md-default-fg-color--lightest);color:var(--md-default-fg-color--light);}
.ksn__req{font-size:.66rem;color:var(--md-default-fg-color--light);}
.ksn__dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:baseline;}
.ksn__dot--open{background:#3fb950;} .ksn__dot--gated{background:#d29922;} .ksn__dot--closed{background:var(--md-default-fg-color--lighter);}
.ksn__legend{display:flex;flex-wrap:wrap;gap:16px;margin-top:14px;font-size:.7rem;color:var(--md-default-fg-color--light);}
@media (max-width:480px){.ksn__row{grid-template-columns:14px 1fr;}.ksn__rside{grid-column:2;align-items:flex-start;flex-direction:row;}}
</style>

<script>
(function(){
  // Fact base transcribed from this page's prose. build ordinals:
  // 1=<=19H2  2=20H1  3=21H2  4=22H2  5=23H2  6=24H2/25H2
  var CS='../../case-studies/';
  var T=[
    {name:'NtQuerySystemInformation — SystemModuleInformation (class 11)',cat:'API disclosure',
     eval:function(s){
       if(s.build<=1) return ['open','Any IL',{t:'Returns ntoskrnl / driver / HAL base addresses to any process on this build.'}];
       if(s.il==='medium') return ['gated','Medium IL',{t:'Restricted to Medium IL from 20H1; you have it. Returns module bases directly.'}];
       return ['gated','Needs Medium IL / SD corruption',{t:'Low-IL access closed from 20H1. Unlock it from Low IL with SepMediumDaclSd corruption below if you hold a write primitive.'}];
     }},
    {name:'NtQuerySystemInformation — SystemBigPoolInformation (class 66)',cat:'API disclosure',
     eval:function(s){
       if(s.build<=1) return ['open','Any IL',{t:'Leaks big-pool allocation addresses and tags — locate specific kernel objects.'}];
       if(s.il==='medium') return ['gated','Medium IL, partial',{t:'Tightened at 21H1–21H2; some allocation data still returns at Medium IL.'}];
       return ['closed','Restricted',{t:'Progressively restricted from 20H1; not available at Low IL on this build.'}];
     }},
    {name:'NtQuerySystemInformation — SystemExtendedHandleInformation (class 64)',cat:'API disclosure',
     eval:function(s){
       if(s.build<=1) return ['open','Any IL',{t:'Handle-table entries expose kernel object pointers (processes, tokens, threads).'}];
       if(s.il==='medium') return ['gated','Medium IL, partial',{t:'Restricted in later builds; some object pointers still reachable at Medium IL.'}];
       return ['closed','Restricted',{t:'Not available at Low IL on this build.'}];
     }},
    {name:'EnumDeviceDrivers / GetDeviceDriverBaseAddress (PSAPI)',cat:'API disclosure',
     eval:function(s){
       if(s.build>=6) return ['closed','Elevated only on 24H2',{t:'PSAPI wrapper over NtQuerySystemInformation; restricted to elevated callers from 24H2.'}];
       if(s.build<=1||s.il==='medium') return ['open','Non-elevated OK',{t:'Simpler interface to the same module-base data; open to non-elevated callers before 24H2.'}];
       return ['gated','Needs Medium IL',{t:'Follows the NtQuerySystemInformation IL gate.'}];
     }},
    {name:'NtQueryVirtualMemory — MemoryWorkingSetExInformation',cat:'API disclosure (indirect)',
     eval:function(s){ return ['open','Any IL',{t:'Leaks page-frame numbers and VA metadata; infer kernel layout from working-set analysis. No documented IL restriction.'}]; }},
    {name:'ETW kernel-logger pointer leaks',cat:'ETW',
     eval:function(s){
       if(s.build<=3) return ['open','ETW session',{t:'Kernel-logger event payloads and create-callback data expose raw pointers pre-22H2.'}];
       return ['closed','Patched 22H2',{t:'Most pointer leaks fixed in 22H2 (backported to 21H2). Surface is broad, so new vectors still surface occasionally.'}];
     }},
    {name:'Prefetch timing side-channel',cat:'Timing side-channel',
     eval:function(s){
       if(s.cpu==='amd') return ['gated','Intel-reliable',{t:'prefetch + rdtsc over the 256 candidate bases. Inconsistent on AMD; needs KVA shadowing disabled.'}];
       return ['open','No vuln, no priv',{t:'prefetch + rdtsc latency over 256 bases; works on 24H2 with KVA shadow off. Reliable on Intel'+(s.cpu==='any'?', inconsistent on AMD':'')+'. <a href="https://exploits.forsale/24h2-nt-exploit/" target="_blank" rel="noopener">24H2 NT Exploit</a>.'}];
     }},
    {name:'Entropy brute-force (256 bases)',cat:'Timing side-channel',
     eval:function(s){ return ['gated','Seed leak',{t:'Only 8 bits. Once any partial leak narrows the range, enumerate the rest. An amplifier, not a standalone leak.'}]; }},
    {name:'Interrupt timing side-channel',cat:'Timing side-channel',
     eval:function(s){ return ['open','No vuln, no priv',{t:'Interrupt-handling time varies with cache state, correlating with layout. Lower bandwidth and less reliable than prefetch.'}]; }},
    {name:'SepMediumDaclSd — DACL zeroing',cat:'SD corruption',
     eval:function(s){
       if(s.write) return ['open','Have write',{t:'Zero the global DACL (e.g. RtlClearAllBits) to drop the IL gate; Low-IL can then query module addresses. See <a href="../../primitives/exploitation/acl-sd-manipulation/">ACL / SD Manipulation</a>.'}];
       return ['gated','Needs arbitrary write',{t:'Converts an arbitrary-write primitive into a KASLR bypass — no info-leak vuln needed. Structural, works across modern builds.'}];
     }},
    {name:'SepMediumDaclSd — Control bit-flip (SE_SACL_PRESENT)',cat:'SD corruption',
     eval:function(s){
       if(s.write||s.bitflip) return ['open','Have bit-flip',{t:'Clear the 0x10 Control bit so SeAccessCheck skips MIC validation — one bit defeats DACL + integrity checks. StarLabs used <a href="'+CS+'CVE-2024-30088/">CVE-2024-30088</a>.'}];
       return ['gated','Needs bit-flip / partial write',{t:'A single-bit variant of DACL corruption; the cheapest SD-corruption path.'}];
     }},
    {name:'WIL feature-flag bypass (Feature_RestrictKernelAddressLeaks)',cat:'SD corruption',
     eval:function(s){
       if(s.write||s.bitflip) return ['open','Have bit-set',{t:'Flip the WIL runtime flag with RtlSetBit to stop address scrubbing; pair with DACL zeroing to fully defeat NtQuerySystemInformation restrictions. Chain: <a href="'+CS+'CVE-2026-21241/">CVE-2026-21241</a>.'}];
       return ['gated','Needs bit-set primitive',{t:'Defeats the secondary gate Microsoft added after the DACL restrictions. Combine with DACL corruption.'}];
     }},
    {name:'Driver-specific info-disclosure vuln',cat:'Driver info leak',
     eval:function(s){
       return ['gated','Needs an unpatched driver leak',{t:'The most practical bypass on a fully patched system with no write primitive. Browse candidates by patched build in the <a href="../../explore/">Explore</a> table (filter Vuln Class = Uninitialized Memory / Arbitrary R-W). Known leaks: '+
         '<a href="'+CS+'CVE-2024-38256/">CVE-2024-38256</a>, <a href="'+CS+'CVE-2024-21338/">CVE-2024-21338</a>, <a href="'+CS+'CVE-2023-32019/">CVE-2023-32019</a>.'}];
     }}
  ];
  var wrap=document.currentScript.closest('article')||document;
  function $(id){return document.getElementById(id);}
  function read(){
    return {build:parseInt($('ksn-build').value,10),il:$('ksn-il').value,cpu:$('ksn-cpu').value,
            write:$('ksn-write').checked,bitflip:$('ksn-bitflip').checked};
  }
  function render(){
    var s=read(),only=$('ksn-only').checked,list=$('ksn-list'),html='',open=0,shown=0;
    T.forEach(function(t){
      var r=t.eval(s),status=r[0],req=r[1],info=r[2];
      if(status==='open') open++;
      if(only&&status!=='open') return;
      shown++;
      html+='<div class="ksn__row ksn__row--'+status+'">'+
        '<span class="ksn__rdot ksn__pill--'+status+'" style="background:'+({open:'#3fb950',gated:'#d29922',closed:'var(--md-default-fg-color--lighter)'}[status])+'"></span>'+
        '<div class="ksn__rmain"><div class="ksn__rname">'+t.name+'</div>'+
        '<div class="ksn__rcat">'+t.cat+'</div>'+
        '<div class="ksn__rwhy">'+info.t+'</div></div>'+
        '<div class="ksn__rside"><span class="ksn__pill ksn__pill--'+status+'">'+status+'</span>'+
        '<span class="ksn__req">'+req+'</span></div>'+
        '</div>';
    });
    list.innerHTML=html||'<div class="ksn__rwhy" style="padding:8px 2px">No techniques are open for this situation. Widen your access, add a primitive, or drop the &ldquo;only open&rdquo; filter.</div>';
    $('ksn-count').textContent=open+' of '+T.length+' open for this target'+(only?' · '+shown+' shown':'');
  }
  ['ksn-build','ksn-il','ksn-cpu','ksn-write','ksn-bitflip','ksn-only'].forEach(function(id){
    var el=$(id); if(el) el.addEventListener('change',render);
  });
  render();
})();
</script>

## Information Disclosure APIs

The original sin of Windows KASLR was exposing kernel addresses through documented APIs. For years, any process could call `NtQuerySystemInformation` and receive a complete map of the kernel's address space.

### NtQuerySystemInformation

Three information classes were particularly useful to attackers. **SystemModuleInformation (class 11)** returns the load addresses of every kernel module, giving the attacker the base address of `ntoskrnl.exe`, all loaded drivers, and the HAL. This was available to any process until Windows 10 20H1, which restricted it to Medium integrity level and above. **SystemBigPoolInformation (class 66)** leaked the addresses of large pool allocations along with their pool tags, allowing attackers to locate specific kernel objects in memory. **SystemExtendedHandleInformation (class 64)** returned handle table entries including kernel object pointers, revealing the addresses of processes, threads, tokens, and other objects referenced by open handles. Both were restricted in later builds, though some information remains available at Medium IL.

### Other APIs

**EnumDeviceDrivers** and **GetDeviceDriverBaseAddress** are PSAPI wrappers around `NtQuerySystemInformation` that provide a simpler interface to the same data. Windows 11 24H2 restricted these for non-elevated callers. **NtQueryVirtualMemory with MemoryWorkingSetExInformation** leaks page frame numbers and virtual address metadata, which can be used to infer kernel memory layout through working set analysis.

## ETW-Based Leaks

Event Tracing for Windows kernel logger sessions historically exposed kernel pointers through event payloads. Certain event classes included raw pointer values in their data fields, and thread and process creation events logged kernel addresses in callback data. Circular buffer timing attacks allowed inferring kernel activity patterns from event sequencing. Microsoft patched most pointer leaks in Windows 11 22H2 and backported fixes to 21H2 via servicing updates, but the ETW attack surface remains broad enough that new leak vectors occasionally surface.

## Timing Side-Channels

Hardware-level side channels bypass all software restrictions. They require no vulnerability, no elevated privileges, and no cooperation from any API.

The most practical technique is **prefetch timing**. The `prefetch` instruction executes faster when the target virtual address is present in the current page tables. On Windows 11 24H2 with KVA shadowing disabled, kernel pages remain in user-mode page tables, meaning a user-mode process can probe the 256 candidate kernel base addresses by measuring `prefetch` + `rdtsc` latency for each one. The correct base address produces a measurably faster execution time. This works reliably on Intel CPUs but produces inconsistent results on AMD. The technique requires no software vulnerability and has been publicly documented in the [24H2 NT Exploit](https://exploits.forsale/24h2-nt-exploit/) writeup.

With only 256 possible bases, **entropy brute-force** is also viable. A partial information leak that narrows the search space even slightly enables enumeration of all remaining possibilities. **Interrupt timing** provides another channel: kernel interrupt handling time varies with cache state, which correlates with address layout, though this technique is lower-bandwidth and less reliable than prefetch timing.

Microsoft has not fully mitigated these hardware channels. Windows 11 24H2 increased entropy but did not eliminate the timing differentials that make prefetch-based leaks possible.

## Security Descriptor Corruption

This category is the most consequential development in KASLR bypass techniques. With an arbitrary write or [bit-manipulation primitive](../primitives/exploitation/bit-manipulation.md), KASLR restrictions can be removed by corrupting the kernel structures that enforce them. No information disclosure vulnerability is needed because the attacker converts their write primitive into a KASLR bypass directly.

**SepMediumDaclSd DACL zeroing** targets the global security descriptor that gates `NtQuerySystemInformation` access for sensitive information classes. Zeroing the DACL (for example, via `RtlClearAllBits`) removes the integrity level check, letting Low-IL processes query kernel module addresses. See [ACL / SD Manipulation](../primitives/exploitation/acl-sd-manipulation.md).

**SepMediumDaclSd Control bit-flip** is a more surgical variant. Clearing the `SE_SACL_PRESENT` (0x10) bit in the descriptor's `Control` field tricks `SeAccessCheck` into skipping mandatory integrity check (MIC) validation entirely, bypassing both DACL and integrity label checks with a single bit write. The StarLabs team demonstrated this technique in their [Chrome sandbox escape](https://starlabs.sg/blog/2025/07-fooling-the-sandbox-a-chrome-atic-escape/) using CVE-2024-30088's partial write primitive.

**WIL feature flag bypass** defeats the secondary gate that Microsoft added after the DACL-based restrictions. The WIL runtime flag `Feature_RestrictKernelAddressLeaks__private_featureState` controls whether kernel addresses are scrubbed from API output even after the DACL check passes. Flipping its state bits via `RtlSetBit` disables the scrubbing. Combined with DACL corruption, this two-step approach fully defeats `NtQuerySystemInformation` restrictions on modern Windows. Demonstrated in [CVE-2026-21241](../case-studies/CVE-2026-21241.md).

The security descriptor corruption approach matters because it converts any write primitive into a KASLR bypass. An attacker who finds a pool overflow or a bit-flip no longer needs a separate information disclosure vulnerability. They can use their existing primitive to unlock the API-based leaks, then proceed to use those leaked addresses for the rest of the exploit chain.

## Driver Info Disclosure CVEs

Individual driver vulnerabilities that leak kernel pointers continue to appear regularly. Each is patched when discovered, but the steady rate of new disclosures means driver-specific info leaks remain the most practical KASLR bypass on fully patched systems where security descriptor corruption is not available.

| CVE | Driver | Leak Type | Patched Build |
|-----|--------|-----------|---------------|
| CVE-2024-38256 | `win32kfull.sys` | Kernel pointer leak via GDI information class | 10.0.26100 (24H2) |
| CVE-2024-21338 | `appid.sys` | Kernel address disclosure via IOCTL return data | 10.0.22621.3155 (22H2) |
| CVE-2023-32019 | `ntoskrnl.exe` | Kernel memory disclosure via information class | 10.0.22621.1928 (22H2) |
| CVE-2023-36038 | `HTTP.sys` | Kernel stack address leak | 10.0.22621.2506 (22H2) |
| CVE-2022-21881 | `win32k.sys` | Kernel pointer leak via window message handling | 10.0.19041.1466 (21H2) |

## Windows Version Timeline

| Version | KASLR Entropy | Key Changes |
|---------|---------------|-------------|
| RS1-RS5 (2016-2018) | ~8 bits | Basic KASLR. All info disclosure APIs available at any IL. |
| 19H1-19H2 (2019) | ~8 bits | No KASLR changes. |
| 20H1-20H2 (2020) | ~8 bits | `NtQuerySystemInformation` restricted for Low-IL. Sandbox escape now required for API-based leaks. |
| 21H1-21H2 (2021) | ~8 bits | `SystemBigPoolInformation` access tightened. |
| 22H2 (2022) | ~8 bits | ETW pointer leak fixes. Multiple info disclosure CVEs patched. |
| 23H2 (2023) | ~8 bits | Incremental API hardening. |
| 24H2 (2024) | Increased | `EnumDeviceDrivers` restricted for non-elevated callers. Kernel base entropy expanded. Most reliable remaining vector: driver-specific info disclosure vulns. |

## The State of KASLR on 24H2

On a fully patched Windows 11 24H2 system, the practical bypass landscape has narrowed but not closed. Four vectors remain viable.

**Driver-specific information disclosure vulnerabilities** are the most practical method. New info leak CVEs appear regularly across kernel components, and the window between discovery and patch is often wide enough for exploitation.

**Security descriptor corruption** (SepMediumDaclSd + WIL flag) converts any write primitive into a full KASLR bypass without requiring a dedicated information disclosure vulnerability. This is the preferred approach for exploit chains that already have a write or bit-manipulation primitive, as demonstrated in [CVE-2026-21241](../case-studies/CVE-2026-21241.md).

**Prefetch side-channel** works on Intel CPUs without any software vulnerability, providing a hardware-based leak that software patches cannot fully address.

**Medium-IL NtQuerySystemInformation** still returns some kernel information to non-sandboxed processes, though the most sensitive classes have been progressively restricted.

The trajectory is clear: API-based leaks are being closed, forcing attackers toward either hardware side-channels or the more sophisticated security descriptor corruption approach that turns a write primitive into a KASLR bypass. The latter technique is particularly significant because it means KASLR is only as strong as the integrity of the kernel structures that enforce its API restrictions.

## See Also

- [KASLR](kaslr.md) -- overview of the mitigation mechanism
- [ACL / SD Manipulation](../primitives/exploitation/acl-sd-manipulation.md) -- SepMediumDaclSd corruption technique
- [Bit-Manipulation Primitives](../primitives/exploitation/bit-manipulation.md) -- RtlSetBit/RtlClearAllBits used for SD and feature flag corruption
- [CVE-2026-21241](../case-studies/CVE-2026-21241.md) -- full exploit chain using SD corruption + WIL bypass for KASLR defeat
