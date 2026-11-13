# Positioning

This document records where PatchProof sits in the market and how to talk about
it. It combines a landscape scan of AI patching tools (2025–2026) with a
simulated marketing-council review.

## The one-sentence position

> For security and platform engineers who need proof that a vulnerability is
> actually fixed, PatchProof is an open-source CLI that verifies a patch by
> re-running the exploit — and its variants — against the live app, unlike SAST
> auto-fixers that only re-run the scanner.

Competitive alternatives it must beat: (1) manual re-testing by hand, (2)
trusting a SAST auto-fixer's "finding closed" signal, (3) doing nothing and
hoping the patch worked.

## Landscape: how "verified" is defined today

| Tool / system | Patch oracle | Runs exploit? | Runs tests? | Emits attestation? |
|---|---|---|---|---|
| Copilot Autofix, Snyk Agent Fix, Semgrep, Veracode, Checkmarx, Aikido, Mobb | re-run the SAST scanner | no | some (claimed) | no |
| Pixee | scanner + fix-evaluation agent + customer CI | no | yes (claimed) | no |
| OpenAI Aardvark / Codex Security | sandbox exploit of the *finding* | yes (of finding) | unclear | no |
| Google CodeMender | diff/fuzz/SMT + LLM judge, human-reviewed | partial | yes | no |
| DARPA AIxCC finalists | PoV replay + variant PoVs + functional tests | **yes** | **yes** | no |
| Benchmarks (CyberGym, PatchEval, Vul4J, ARVO) | PoC fails post-patch + unit tests | **yes** | **yes** | n/a |
| **PatchProof** | **HTTP exploit + variants blocked + your tests** | **yes** | **yes** | **yes (in-toto)** |

The execution-based bar exists for C/C++ fuzz crashes in research and in the
AIxCC competition. No shipping product applies it to **deployed web apps with
HTTP-level PoCs**, replays **variant** exploits, and emits a **portable
attestation**. That intersection is the empty cell PatchProof occupies.

Key cautions from the same literature, which the product deliberately honors:

- Patches that pass replay + tests can still be semantically wrong (20–40% in
  Team Atlanta 2026; only 26% "clean" in 1Password FLAWED 2026) → honest
  labels, `semantic_review: none`.
- Single-PoC oracles reward WAF-style string blocks → variant replay.
- Over-blocking breaks legitimate behavior → regression gate (and a documented
  path to a benign-twin probe).
- PoC content is an injection/escape vector → PoC-as-data, no-egress sandbox.

## Simulated marketing council

> Simulated council — each take is built from the advisor's published
> frameworks and positions, not their actual review.

**Seated:** April Dunford (positioning), Seth Godin (smallest viable audience),
Ann Handley (voice/content), Byron Sharp (dissenter on differentiation).

### April Dunford — positioning against the real alternative
The trap here is positioning PatchProof as "another AI patching tool," head-to-
head with Copilot Autofix and Snyk, where it loses on brand and budget. Reframe
the market category to **patch verification**, where the competitive alternative
is a scanner re-run or a human manually re-testing. The unique attribute —
re-running the actual exploit and its variants — enables a value the
alternatives cannot claim: evidence of exploitability, not pattern absence. The
sales line writes itself: "your auto-fixer tells you the alert closed;
PatchProof shows you the exploit no longer runs." Lead with that wedge; let the
LLM-patching feature be secondary, because the verification layer is defensible
and the generation layer is commoditized.
**Bottom line:** Sell the verdict, not the generator; the category is proof, not auto-fix.

### Seth Godin — the smallest viable audience
Do not market this to "all developers." Market it to the few hundred security
engineers and AppSec leads who already feel the pain of unverifiable patches and
who talk to each other. Make it remarkable to exactly them: a tool that is
honest enough to print `WEAK PATCH` and `semantic_review: none` when a lesser
tool would claim victory. That candor is the purple cow in a category full of
inflated merge-rate stats. They will tell the next engineer.
**Bottom line:** Win the trust of a small, vocal AppSec tribe with radical honesty about limits.

### Ann Handley — voice and the honest artifact
The attestation is the content. Most tools in this space bury limitations;
PatchProof ships a machine-readable disclaimer. Write everything — README,
attestation prose, verdict strings — to one skeptical security engineer who has
been burned by a "fixed" label before. The bravest version is to make the
failure modes (WEAK, PATCH BROKE TESTS) first-class and well-explained, not
hidden. Voice that says "here is exactly what we proved and what we did not" is
the differentiation.
**Bottom line:** Make the honest attestation the story; write to one burned engineer.

### Byron Sharp — the dissent
Buyers may not perceive "exploit-verified vs scanner-verified" as a real
difference; in practice many teams buy the tool their scanner vendor already
bundles. Differentiation you can see in a demo is not the same as mental
availability at purchase time. So the growth lever is not a sharper claim — it
is distinctiveness and reach: a recognizable name, the AIxCC-credible story
repeated everywhere security people look (CI marketplaces, conference CFPs,
PoC repos), and dead-simple adoption (`pip install`, one CI line). Don't
out-argue the incumbents; out-show-up them where the category's light buyers
are.
**Bottom line:** Distinctiveness and distribution beat a cleverer differentiation claim.

### Where the council disagrees
1. **Niche trust (Godin/Handley) vs. reach (Sharp).** Delight a small AppSec
   tribe, or chase broad mental availability? For an unfunded open-source
   showcase, the binding constraint is credibility, not reach — start with the
   tribe, instrument for word-of-mouth. Revisit if it gets commercial backing.
2. **Differentiation (Dunford) vs. distinctiveness (Sharp).** Is "exploit-
   verified" a buying reason or just a demo moment? Settle it empirically: put
   the one-liner in front of AppSec leads and watch whether they can repeat the
   wedge back. If they can't, Sharp is right and the work is naming + presence.
3. **Honesty as a feature (Handley) vs. honesty as a conversion risk.** The
   `semantic_review: none` candor builds trust but complicates a clean "fixed"
   headline. Resolution: keep the honesty; it is the moat in a category full of
   inflated numbers.

### Chair's synthesis
Position PatchProof in the **patch-verification** category, against scanner
re-runs and manual re-testing, not against auto-fixers. Lead with the verdict
and the variant replay; treat LLM generation as a plug-in detail. Aim first at
the small, vocal AppSec audience and make honesty (`WEAK`, `semantic_review:
none`, the disclaimer in every attestation) the remarkable, repeatable thing.
Keep adoption friction near zero (`pip install`, one CI line) so distribution
compounds.

- **Do:** (1) lead the README with "exploit-verified, not scanner-verified";
  (2) keep variant replay and honest labels front-and-center; (3) ship the
  one-line CI gate as the primary call to action; (4) tell the AIxCC-aligned
  story wherever AppSec engineers look.
- **Tripwire (Sharp):** if AppSec leads can't repeat the wedge unprompted, the
  gap is distribution and naming, not the claim — invest there.
- **Execute with:** `content-strategy` / `launch` for the tribe rollout;
  `landing-page-design` for the one-liner; `ab-testing` to settle disagreement #2.
