---
description: "App Control for Business, formerly WDAC: kernel-enforced application control. Why the signed-policy configuration is the only one that resists a local administrator, and what a kernel primitive does to the rest."
---

# App Control for Business

<div class="ks-pipeline-pos">
  <a href="../driver-types/">Getting in</a> &rarr; <span class="ks-hinge">kernel access</span> &rarr; <span class="ks-half">What stops them</span> <span class="ks-active">User layer</span>
</div>

App Control for Business, known as Windows Defender Application Control until Microsoft renamed
it, decides which code may execute according to a policy an organisation writes. It is enforced
by the same kernel Code Integrity engine as [Smart App Control](smart-app-control.md), and it
takes effect early in boot, before nearly all other operating system code and well before any
security agent starts.

That places it in an unusual position for this reference. Most defenses here are a decision
stored in kernel memory that a kernel primitive can simply edit. This one can be configured so
that the decision is cryptographically signed and checked, and that configuration is the single
most attacker-resistant control in the corpus.

| | |
|---|---|
| Layer | User. The protected asset is user-mode code execution. |
| Enforced by | Kernel. Code Integrity, before the image is mapped, from early boot. |
| Policy on disk | `\Windows\System32\CodeIntegrity\SiPolicy.p7b`, or under `\Microsoft\Boot\` on the EFI system partition. |
| Also governs | Kernel drivers, through the same engine. See [the driver blocklist](index.md). |

## The configuration is the whole story

Four states matter, and they are not degrees of the same thing. They are different security
properties.

**No policy.** The default on almost every machine. App Control is opt-in and enterprise-driven,
so absence is the norm rather than a misconfiguration.

**Audit mode.** The policy is deployed and evaluated, violations are logged, and nothing is
blocked. Audit policies are explicitly not UEFI locked. Audit is where most deployments live
longest, because building an allowlist that does not break a fleet is genuinely hard.

**Enforced, unsigned policy.** Blocking, but the policy file is just a file. An administrator, or
malware holding administrator, can replace or delete it and reboot.

**Enforced, signed policy, with UEFI Secure Boot.** After the first reboot the anti-tampering
protection engages. The installed policy names the certificates permitted to sign future
updates, so a replacement that is not signed by an authorised certificate is rejected. Tampering
with or removing the policy causes a bugcheck rather than a silent downgrade.

Only the fourth state resists a local administrator. The gap between the third and the fourth is
larger than the gap between having no policy and having one.

## Bypass inventory

<div id="acb-nav"></div>

<script>
(window.__ksnav = window.__ksnav || []).push({
  sel:'#acb-nav',
  title:'App Control for Business',
  sub:'Five routes. The policy state control decides almost everything; note how much changes between an unsigned enforced policy and a signed one.',
  fromPlatform:function(p){
    // The site-wide matrix has no App Control selector, so it evaluates against
    // the state almost every machine is in: no policy deployed. Use the selector
    // on this page for the enforcing configurations.
    return {policy:'none', blockrules:false, kwrite:p.prims, admin:p.admin};
  },
  controls:[
    {id:'policy',label:'Policy state on the target',type:'select',default:'none',options:[['none','No policy, the common case'],['audit','Audit mode, logs only'],['unsigned','Enforced, unsigned policy'],['signed','Enforced, signed policy with UEFI lock']]},
    {id:'acb_held',label:'What you hold',type:'checks',wide:true,options:[['admin','administrator'],['kwrite','kernel write primitive'],['blockrules','recommended block rules are merged',true]]}
  ],
  techniques:(function(){return [
    {name:'No policy is deployed',cat:'absent-gate',layer:'user',asOf:'2026-09-07',basis:'cited',ev:function(s){
      if(s.policy!=='none') return ['closed','A policy is present','Does not apply once a policy exists.'];
      return ['open','Nothing required','App Control is opt-in and enterprise-driven. On most machines it has never been configured, so there is nothing to bypass. This is the ordinary case, not an edge case.'];}},
    {name:'Policy is in audit mode',cat:'absent-gate',layer:'user',asOf:'2026-09-07',basis:'cited',ev:function(s){
      if(s.policy!=='audit') return ['closed','Not in audit','Does not apply.'];
      return ['open','Nothing required','Audit evaluates and logs but blocks nothing, and audit policies are not UEFI locked. Deployments sit here for a long time because building an allowlist that does not break a fleet is hard. The logs are real and useful; the enforcement is not there.'];}},
    {name:'Replace or delete the policy file',cat:'privilege-object',layer:'user',asOf:'2026-09-07',basis:'cited',ev:function(s){
      if(s.policy==='none'||s.policy==='audit') return ['closed','Nothing enforcing','No enforcement to remove.'];
      if(s.policy==='signed') return ['closed','Signed policy with UEFI lock','This is what signing exists to stop. Only a certificate the installed policy authorises can sign a replacement, and tampering with or removing the policy causes a bugcheck rather than a quiet downgrade.'];
      if(!s.admin) return ['gated','Needs administrator','The policy lives in a protected system location.'];
      return ['open','Have administrator','An unsigned policy is a file. Replace or delete it, reboot, and enforcement is gone. No exploit involved.'];}},
    {name:'Trusted signed binary that runs arbitrary code',cat:'logic-bug',layer:'user',asOf:'2026-09-07',basis:'cited',ev:function(s){
      if(s.policy==='none'||s.policy==='audit') return ['closed','Nothing enforcing','Irrelevant when nothing is blocked.'];
      if(s.blockrules) return ['gated','Block rules merged','Microsoft publishes a recommended block list precisely because signed Microsoft tooling can execute arbitrary code inside a trusted process. Merged, the known set is denied, and the rules match on the OriginalFileName in the PE version resource, so renaming the file does not help. The list covers what is known, not what exists.'];
      return ['open','Block rules not merged','Signed Microsoft binaries such as the build and scripting hosts execute attacker-supplied code inside a process the policy trusts. The policy is satisfied because the check is on the image, not on what the image goes on to do.'];}},
    {name:'Edit the enforced policy state from kernel',cat:'integrity-check-evasion',layer:'user',asOf:'2026-09-07',basis:'inferred',ev:function(s){
      if(s.policy==='none'||s.policy==='audit') return ['closed','Nothing enforcing','Nothing to edit.'];
      if(!s.kwrite) return ['gated','Needs a kernel write primitive','The enforced state is Code Integrity data in kernel memory.'];
      if(s.policy==='signed') return ['gated','Signed, but the check is at load','Reasoning, not a demonstrated result: the signature is validated when the policy is loaded, while enforcement then proceeds from state held in kernel memory. Editing that state would not touch the file the anti-tampering protection guards. Recorded as inferred because no public work demonstrates it, and the boot-time and periodic protections around a signed policy are exactly the kind of thing that would decide it.'];
      return ['open','Have kernel write','With an unsigned policy the enforced state is ordinary kernel data. FudModule does this to Smart App Control, which rides the same engine.'];}}
  ];})()
});
</script>

## What a defender sees

The routes that matter produce very different amounts of evidence.

- **Policy file replaced or deleted.** Loud on a machine you are watching, and it requires a
  reboot to take effect, which is a second signal. Alert on the file, not just on the setting.
- **A trusted binary spawning unusual children, or reading script content from an unusual
  place.** This is the route with no policy violation to log, because nothing was violated. It
  has to be caught behaviourally.
- **Bugchecks on a signed-policy fleet.** A tamper attempt against a signed policy is designed to
  fail loudly. Treat an unexplained bugcheck on a locked-down machine as a security event rather
  than a stability one.
- **Machines with no policy, or stuck in audit.** Not an alert, an inventory question. It is
  worth knowing what proportion of a fleet is actually enforcing, because that number is usually
  lower than people assume.

## Where this sits among the others

Four features in this corpus answer "may this code run", and they differ by who holds the
authority:

- **App Control for Business** asks a policy your organisation wrote, and can sign.
- **[Smart App Control](smart-app-control.md)** asks Microsoft's reputation service.
- **AppLocker** asks a rule set enforced later and more weakly.
- **The vulnerable driver blocklist** is a policy in this same family, applied to kernel drivers
  rather than user-mode code. It is why the BYOVD technique has a shelf life, and why
  [CVE-2026-68820](../case-studies/CVE-2026-68820.md) went around it by using a driver that
  ships with Windows and can never be blocked.

The signed configuration is the interesting one for this whole reference, because it is the only
place in the user layer where the answer to "what does a kernel primitive buy" is not obviously
everything. Every other user-layer defense here stores its decision somewhere the kernel can
reach and edit. This one stores a signature check as well, and whether that survives a kernel
primitive is an open question rather than a settled one.
