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

## Bypass inventory

<div id="ppl-nav"></div>

<script>
(window.__ksnav = window.__ksnav || []).push({
  sel:'#ppl-nav',
  title:'Protected Process Light',
  sub:'Three techniques. Each assumes an existing kernel write primitive; PPL is what that primitive is spent on, not an obstacle to obtaining it.',
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
