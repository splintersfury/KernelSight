---
description: "A seven-stage path through Windows kernel security, from why a driver bug matters through to what kernel access is actually worth. Each stage names what you will be able to do at the end of it."
---

# Start here

This is an ordered path through the site. It assumes you know Windows as a user or a developer,
and nothing about kernel exploitation. Each stage tells you what you should be able to do when
you finish it, so you can tell whether to move on or reread.

There are seven stages. Doing all of them properly is a few evenings, not an afternoon. Skipping
ahead is fine if a stage's check question is already easy for you.

!!! note "How to use this"
    Read the linked pages in the order given, then answer the check question in your own words
    without looking. If you cannot, reread that stage. The questions are the point; the reading
    is just how you get there.

---

## Stage 1: Why the kernel is the whole game

**The idea.** Windows enforces every security decision you care about, who may read a file, who
may open a process, which code may run, in kernel memory. Code running in the kernel is not
merely privileged. It is on the same side of the boundary as the thing doing the enforcing.

**Read.** [Why kernel drivers?](guides/why-kernel-drivers.md), then skim
[Driver types](driver-types/index.md) to see how much third-party code runs there.

**You should be able to say why** an antivirus product asking you to install a driver is asking
for something categorically larger than an ordinary application permission.

**Check.** A colleague says "the exploit only got kernel read, not write, so it is low severity."
What is wrong with that reasoning?

---

## Stage 2: How your code reaches a driver

**The idea.** A driver is not reachable by accident. Something has to carry your input across
the boundary, and that path is short, well defined, and where most bugs live.

**Read.** [Attack surfaces](attack-surfaces/index.md), then
[IOCTL handlers](attack-surfaces/ioctl-handlers.md) in full. IOCTLs are the single most
productive surface in the corpus, so it is worth the time.

**You should be able to explain** what `METHOD_NEITHER` means and why it puts the burden of
validating pointers on the driver author rather than on Windows.

**Check.** A driver exposes a device object any user can open. Is that a vulnerability?

---

## Stage 3: What actually goes wrong

**The idea.** Kernel bugs are not exotic. They are the same handful of mistakes as user-mode
bugs, with the consequences multiplied.

**Read.** [Vulnerability classes](vuln-classes/index.md), then at minimum
[buffer overflow](vuln-classes/buffer-overflow.md),
[use after free](vuln-classes/use-after-free.md) and
[TOCTOU and double fetch](vuln-classes/toctou-double-fetch.md).

**You should be able to name** the class from a description of the bug, and say what kind of
corruption each one hands you.

**Check.** Why is a double fetch a bug even when both reads validate the value correctly?

---

## Stage 4: The worked example

**The idea.** This is where the previous three stages meet. Read one real vulnerability all the
way through before reading any more theory.

**Read.** [CVE-2024-21338](case-studies/CVE-2024-21338.md), the AppLocker driver. Three design
failures compound into arbitrary kernel read and write with no race, no heap grooming and no
information leak required. Lazarus Group used it to load a rootkit without dropping a driver at
all, because the vulnerable driver was already on every Windows machine.

**You should be able to trace** the path from a `DeviceIoControl` call in user mode to a write
at an address the caller chose.

**Check.** The driver ships as part of a security feature. Why did that make it more useful to
the attacker, not less?

---

## Stage 5: Turning a bug into control

**The idea.** A bug gives you one corruption. Exploitation is the craft of converting that into
a general capability, and then converting the capability into privilege.

**Read.** [Primitives](primitives/index.md), then
[write what where](primitives/arw/write-what-where.md),
[token swapping](primitives/exploitation/token-swapping.md) and
[PreviousMode manipulation](primitives/exploitation/previous-mode-manipulation.md).

**You should be able to explain** why attackers so often stop at a data-only change rather than
running shellcode in the kernel.

**Check.** You have a single arbitrary write of one controlled byte, once. Is that enough?

---

## Stage 6: What stops you

**The idea.** Windows has spent fifteen years taxing each step of stage 5. No single defense
stops exploitation. Together they decide which bugs remain worth the effort.

**Read.** [SMEP and SMAP](mitigations/smep-smap.md),
[kCFG and kCET](mitigations/kcfg-kcet.md), [VBS and HVCI](mitigations/vbs-hvci.md), and
[KASLR bypasses](mitigations/kaslr-bypasses.md). Each of those pages carries an interactive
inventory: set the build and the CPU features and watch techniques open and close.

**You should be able to say** which defense breaks which specific step of the chain you learned
in stage 5.

**Check.** SMEP blocks the kernel executing user-mode pages. Why did that not end kernel
exploitation?

---

## Stage 7: What kernel access is actually worth

**The idea.** The last question, and the one this site exists to answer. You have the primitive.
What does it buy?

**Read.** [The bypass matrix](bypasses/index.md), then
[Protected Process Light](mitigations/protected-process.md) in full.

**You should be able to explain** why a single byte write defeats Protected Process Light, which
guards antivirus processes, while the same primitive does nothing at all against Credential
Guard, which guards passwords on the same machine.

**Check.** Both defend a user-mode process. What makes one reachable and the other not?

---

## Where to go next

If the check questions were comfortable, the corpus is now a reference rather than a course.
Three ways in:

- **By component.** The deep dives collect every bug in one driver and argue why it keeps
  producing them: [CLFS](case-studies/clfs-deep-dive.md),
  [AFD](case-studies/afd-deep-dive.md), [Win32k](case-studies/win32k-deep-dive.md) and
  [NTFS](case-studies/ntfs-deep-dive.md).
- **By pattern.** [Exploit chain patterns](guides/exploit-chain-patterns.md) shows the shapes
  that recur across unrelated bugs.
- **By driver.** [BYOVD](reference/byovd.md) covers bringing a vulnerable signed driver rather
  than finding a new bug, which is what most real intrusions do.

One honest caveat. Most of this corpus was last revised in March 2026, and every page tells you
its own age at the bottom. The technique inventories carry a dated verdict and a basis tier, so
you can see which claims were tested, which merely cite a source, and which are reasoned but
unconfirmed. Treat an `inferred` verdict as a lead to check, not a fact to rely on.
