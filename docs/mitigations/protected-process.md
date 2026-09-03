# Protected Process Light

Protected Process Light is an access-control decision made in the kernel about kernel objects.
That framing is the whole story of its bypass inventory: an attacker holding a kernel write
primitive is already on the same side of the boundary as the enforcement, so every technique
below edits the decision rather than defeating it.

Contrast this with Credential Guard, where the protected asset lives in VTL1 and the same
primitive buys nothing. That contrast is the clearest statement of where the real boundary
runs, and it is why the two defenses sit beside each other in this section.

| | |
|---|---|
| Layer | User. The protected asset is a user-mode process. |
| Enforced by | Kernel. The object manager checks on handle open. |
| Mechanism | `EPROCESS.Protection`, a byte holding signer and level. |
| Introduced | Windows 8.1, extended for antimalware signers in Windows 10. |

## The signer ladder

`EPROCESS.Protection` packs two fields into one byte: a protection type and a signer. A process
may open another only when its own signer sits at or above the target's. Everything in the
inventory below is a way of editing that byte, or of borrowing a driver that never checks it.

<div class="ks-figure" markdown>
  <span class="ks-figure-label">FIG_009: Protection byte and signer precedence</span>
  <svg viewBox="0 0 820 300" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="The protection byte splits into a type nibble and a signer nibble. Signers rank from WinTcb at the top down to Authenticode, and a process may only open one at or below its own rank.">

    <!-- the byte -->
    <text class="ks-label" x="30" y="28">EPROCESS.Protection, one byte</text>
    <rect class="ks-box" x="30" y="40" width="150" height="42"/>
    <text class="ks-annotation" x="105" y="58" text-anchor="middle">bits 7:4</text>
    <text class="ks-annotation" x="105" y="74" text-anchor="middle">SIGNER</text>
    <rect class="ks-box" x="180" y="40" width="150" height="42"/>
    <text class="ks-annotation" x="255" y="58" text-anchor="middle">bits 3:0</text>
    <text class="ks-annotation" x="255" y="74" text-anchor="middle">TYPE, PP or PPL</text>
    <text class="ks-annotation" x="30" y="104">A kernel write clears both. Nothing recomputes them from the signature.</text>

    <!-- ladder -->
    <text class="ks-label" x="440" y="28">Signer precedence</text>
    <rect class="ks-box" x="440" y="40" width="230" height="30"/>
    <text class="ks-annotation" x="452" y="59">WinTcb, highest</text>
    <rect class="ks-box" x="440" y="76" width="230" height="30"/>
    <text class="ks-annotation" x="452" y="95">Windows</text>
    <rect class="ks-box" x="440" y="112" width="230" height="30"/>
    <text class="ks-annotation" x="452" y="131">Lsa</text>
    <rect class="ks-box" x="440" y="148" width="230" height="30"/>
    <text class="ks-annotation" x="452" y="167">Antimalware, where EDR sits</text>
    <rect class="ks-box" x="440" y="184" width="230" height="30"/>
    <text class="ks-annotation" x="452" y="203">Authenticode, lowest</text>

    <path class="ks-arrow" d="M690 55 L690 199"/>
    <path class="ks-arrow" d="M685 193 L690 203 L695 193 Z" fill="currentColor"/>
    <text class="ks-annotation" x="700" y="120">may open</text>
    <text class="ks-annotation" x="700" y="134">downward</text>

    <!-- where the primitive lands -->
    <line class="ks-line" x1="30" y1="150" x2="410" y2="150" stroke-dasharray="4 3"/>
    <text class="ks-annotation" x="30" y="170">A kernel write primitive does not climb this ladder.</text>
    <text class="ks-annotation" x="30" y="186">It rewrites the rung, which is why every entry below is</text>
    <text class="ks-annotation" x="30" y="202">the same category of work.</text>

    <text class="ks-annotation" x="30" y="248">Contrast Credential Guard: the secret is not guarded by a byte in this</text>
    <text class="ks-annotation" x="30" y="264">structure, it lives in VTL1, so there is no rung to rewrite.</text>
  </svg>
</div>

## Bypass inventory

<div id="ppl-nav"></div>

<script>
(window.__ksnav = window.__ksnav || []).push({
  sel:'#ppl-nav',
  title:'Protected Process Light',
  sub:'Three techniques. Each assumes an existing kernel write primitive; PPL is what that primitive is spent on, not an obstacle to obtaining it.',
  fromPlatform:function(p){
    return {build:String(p.build), kwrite:p.prims, blocklist:true};
  },
  controls:[
    {id:'build',label:'Build',type:'select',default:'26100',options:[['19041','Windows 10 2004'],['22621','Windows 11 22H2'],['26100','Windows 11 24H2'],['26200','Windows 11 25H2']]},
    {id:'ppl_held',label:'What you hold',type:'checks',wide:true,options:[['kwrite','kernel write primitive',true],['blocklist','driver blocklist is current',true]]}
  ],
  techniques:(function(){var CS='../../case-studies/';return [
    {name:'EPROCESS.Protection downgrade',cat:'privilege-object',layer:'user',asOf:'2026-09-03',basis:'inferred',ev:function(s){
      if(!s.kwrite) return ['gated','Needs a kernel write primitive','The field is kernel-resident, so reaching it requires the primitive first.'];
      return ['open','Have kernel write','The protection level is a single byte in the process object. Clear it and the object manager grants full access on the next open. Nothing re-derives the value from the signing state, so the change persists for the lifetime of the process.'];}},
    {name:'Handle duplication via signed driver',cat:'privilege-object',layer:'user',asOf:'2026-09-03',basis:'cited',ev:function(s){
      if(s.blocklist) return ['gated','Driver is blocklisted','The driver duplicates a full-access handle without consulting the caller protection level, but it is carried on the vulnerable driver blocklist. See <a href="'+CS+'Truesight-sys/">Truesight.sys</a>.'];
      return ['open','Blocklist stale or disabled','With the blocklist out of date, the driver loads and duplicates a full-access handle to any protected process. See <a href="'+CS+'Truesight-sys/">Truesight.sys</a>.'];}},
    {name:'Protected-process termination',cat:'privilege-object',layer:'user',asOf:'2026-09-03',basis:'cited',ev:function(s){
      if(s.blocklist) return ['gated','Driver is blocklisted','Termination reaches an antimalware process without opening a handle the object manager would refuse, because the kill originates in kernel context. Currently blocklisted. See <a href="'+CS+'viragt64-sys/">viragt64.sys</a>.'];
      return ['open','Blocklist stale or disabled','Kernel-context termination of a PPL antimalware process, with no handle open for the object manager to refuse. See <a href="'+CS+'viragt64-sys/">viragt64.sys</a>.'];}}
  ];})()
});
</script>

## Why the inventory looks like this

Every entry above is `privilege-object`. That is not a gap in the research, it is the shape of
the defense. PPL does not encrypt anything, does not validate anything cryptographically at
access time, and does not involve the hypervisor. It stores a decision in kernel memory and
consults it later, so the entire attack surface is that stored decision and the drivers trusted
to act on it.

The practical consequence for a defender is that PPL is worth exactly as much as the integrity
of kernel memory. It is a meaningful barrier to a user-mode adversary and close to none against
one who already holds a kernel write.

## What a defender sees

A process whose protection level changes after creation. The transition is observable to
anything sampling `EPROCESS.Protection`, and no legitimate path performs it, so the signal has
a low false-positive rate.

For the two driver-backed techniques the earlier and louder signal is the driver load itself.
Both are known-vulnerable signed drivers, so blocklist telemetry catches them before they reach
the protected process.
