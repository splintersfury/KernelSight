---
description: "Smart App Control, the Windows 11 reputation-based application control feature: how it is enforced, why it is usually not enabled, and what a kernel primitive does to it."
---

# Smart App Control

<div class="ks-pipeline-pos">
  <a href="../driver-types/">Getting in</a> &rarr; <span class="ks-hinge">kernel access</span> &rarr; <span class="ks-half">What stops them</span> <span class="ks-active">User layer</span>
</div>

Smart App Control decides whether a user-mode program is allowed to run, based on Microsoft's
reputation intelligence rather than on a policy an administrator wrote. It is the consumer-facing
sibling of App Control for Business, and it rides the same kernel Code Integrity engine, so the
decision is made in kernel memory before the image is mapped.

It arrives in this reference for a specific reason. FudModule v3.1, the rootkit Lazarus deployed
through [CVE-2026-68820](../case-studies/CVE-2026-68820.md), tampers with Smart App Control's
policy state directly. That makes it the first user-layer defense in this corpus with a
documented in-the-wild kernel-side attack against it.

| | |
|---|---|
| Layer | User. The protected asset is user-mode code execution. |
| Enforced by | Kernel. The Code Integrity engine, before the image is mapped. |
| Introduced | Windows 11 22H2. |
| States | Evaluation, On, Off. |

## The thing to understand first

Most machines do not have it on, and that is by design rather than by neglect.

A new Windows 11 install starts Smart App Control in **Evaluation** mode, where it blocks
nothing and watches how the machine is used. After roughly a month it turns itself On or Off
depending on what it observed. A machine that runs unsigned or unusual software gets Off, and
Off is where it stays. Upgrades from Windows 10 arrive Off. Managed enterprise fleets generally
run App Control for Business instead.

Historically a machine that reached Off could only get back by resetting Windows, which meant
almost nobody did. The March 2026 servicing update relaxed that, so On and Evaluation can now be
re-selected without a reset.

The practical consequence is the one that matters for a threat model. On a given target, the
most likely reason Smart App Control does not stop something is that it was never enforcing in
the first place. An absent gate beats a bypassed gate every time, and no exploit is required to
walk through one.

## What it actually blocks

When it is On, it is strict in a way most application control is not. There is no per-app
exception, no allowlist an administrator can extend, and no "run anyway" prompt. Code either
satisfies Microsoft's signing and reputation checks or it does not execute. That strictness is
why it is usually Off: it is not tunable enough to survive a machine that does anything unusual.

## Bypass inventory

<div id="sac-nav"></div>

<script>
(window.__ksnav = window.__ksnav || []).push({
  sel:'#sac-nav',
  title:'Smart App Control',
  sub:'Four routes, only one of which needs a kernel primitive. Set the feature state first; it is the control that decides everything else.',
  fromPlatform:function(p){
    // The site-wide matrix has no Smart App Control control, so it evaluates
    // this inventory against the state most real machines are in: Off. Use the
    // selector on this page to see the enforcing case.
    return {build:String(p.build), sac:'off', kwrite:p.prims, admin:p.admin};
  },
  controls:[
    {id:'sac',label:'Feature state on the target',type:'select',default:'off',options:[['off','Off, the common case'],['eval','Evaluation, blocks nothing'],['on','On and enforcing']]},
    {id:'sac_held',label:'What you hold',type:'checks',wide:true,options:[['kwrite','kernel write primitive'],['admin','administrator']]}
  ],
  techniques:(function(){var CS='../../case-studies/';return [
    {name:'The feature is not enforcing',cat:'absent-gate',layer:'user',asOf:'2026-09-07',basis:'cited',ev:function(s){
      if(s.sac==='on') return ['closed','Feature is On','Enforcing, so this route does not apply. Note how narrow that condition is.'];
      return ['open','Nothing required','The most common state on real machines. Evaluation blocks nothing, and Off is where the feature places itself after watching a machine that runs anything unusual. Upgrades from Windows 10 arrive Off. No exploit, no privilege, no artefact.'];}},
    {name:'Policy tampering from kernel',cat:'integrity-check-evasion',layer:'user',asOf:'2026-09-07',basis:'cited',ev:function(s){
      if(s.sac!=='on') return ['closed','Nothing to tamper with','The feature is not enforcing, so editing its policy buys nothing you did not already have.'];
      if(!s.kwrite) return ['gated','Needs a kernel write primitive','The enforced policy is Code Integrity state in kernel memory, so reaching it requires the primitive first.'];
      return ['open','Have kernel write','FudModule v3.1 tampers with the verified-and-reputable policy state directly. The engine keeps enforcing; it is the decision that changed. See <a href="'+CS+'CVE-2026-68820/">CVE-2026-68820</a>.'];}},
    {name:'Administrator disables the feature',cat:'privilege-object',layer:'user',asOf:'2026-09-07',basis:'cited',ev:function(s){
      if(s.sac!=='on') return ['closed','Already not enforcing','Nothing to disable.'];
      if(!s.admin) return ['gated','Needs administrator','The setting is administrator-controlled.'];
      return ['open','Have administrator','Turning it off is a supported operation, not an exploit. It is loud and it is logged, which is the only thing working against it.'];}},
    {name:'Signed or reputable code',cat:'logic-bug',layer:'user',asOf:'2026-09-07',basis:'inferred',ev:function(s){
      if(s.sac!=='on') return ['closed','Feature is not enforcing','Irrelevant when nothing is being checked.'];
      return ['gated','Needs suitable code','The check is signature and reputation, not behaviour. Code that satisfies both runs, whatever it does. Living-off-the-land binaries and abused signed tooling are unaffected by design. Recorded as inferred: this is a design property, not a demonstrated bypass with a citation.'];}}
  ];})()
});
</script>

## What a defender sees

The first three routes are each observable, and the ordering is worth noting because it is the
inverse of how interesting they are.

- **A policy state change with no servicing event.** The strongest signal, and the one FudModule
  produces. Smart App Control's enforcement state should only move when Windows updates it or an
  administrator changes it. A transition with neither is a kernel-side edit.
- **An administrator turning it off.** Supported, logged, and trivial to alert on.
- **The feature sitting in Off.** Not an alert, but it belongs in an inventory. Knowing which of
  your machines are actually enforcing is the difference between a control and a checkbox.

The fourth route produces nothing. Code that satisfies signing and reputation checks is code the
feature was designed to run, so there is no event to collect.

## Relationship to the other application-control defenses

Smart App Control, [App Control for Business](index.md) and AppLocker overlap and
are frequently confused. The short version: they answer the same question with different
authorities. Smart App Control asks Microsoft's reputation service, App Control for Business asks
a policy your organisation wrote and can sign, and AppLocker asks a rule set enforced later and
more weakly.

For an attacker holding a kernel primitive the distinction mostly collapses, because all three
record their decision somewhere the kernel can reach. The exception is a signed App Control
policy, where the signature is validated rather than trusted, which is the one configuration in
this family that does not simply fall to a byte.
