# Evals Primer — the mental model in one hour

Read this once before you build `EVALS_SPEC.md`. Goal: understand *why* each piece exists so you build with intent and can defend every choice in an interview. Eight concepts. Each has: what it is, why it matters, how it maps to your audit agent, and the interview angle.

---

## 1. Why evals exist at all

**What:** An eval is a repeatable test for a system whose output isn't deterministic. Normal code you test with `assert add(2,2) == 4`. But an LLM agent can give a slightly different answer every run, and "is this audit finding good?" has no single exact string to match. So instead of one pass/fail assertion, you measure *how often* the system does the right thing across a set of cases, and track that number over time.

**Why it matters:** Without evals you're flying blind — you change a prompt, it "feels better," and you have no idea if you just broke detection on three bug classes. Evals convert vibes into numbers.

**In your agent:** "Does my audit agent find real bugs?" isn't answerable by looking at one run. It's answerable by running it against 25 contracts with known bugs and counting.

**Interview angle:** "I don't trust 'it feels better' — I ran a fixed benchmark before and after every change so I could see regressions." That sentence alone signals production maturity.

---

## 2. The labeled benchmark (ground truth)

**What:** A fixed set of inputs where you already know the correct answer. For you: vulnerable contracts each paired with a `label.json` saying what the bug is. "Ground truth" = the known-correct answer you compare the agent's output against.

**Why it matters:** You cannot compute *any* accuracy metric without known-correct answers. The quality of your evals is capped by the quality of your labels. Garbage or ambiguous labels → meaningless numbers.

**In your agent:** Your own competitive-audit findings are premium ground truth — you know the exact bug, severity, and root cause. Cyfrin's `sc-exploits-minimized` gives you clean, unambiguous starter cases. Include a few **non-vulnerable** contracts too, or you can't measure false alarms.

**Interview angle:** "I labeled the benchmark from real findings I'd personally validated, plus public exploit datasets, and I deliberately included clean contracts as negative controls." Negative controls = you think like a scientist, not a demo-builder.

---

## 3. Retrieval metrics — Recall@k and MRR

**What:** Your RAG step returns a ranked list of prior findings. Two questions: *did the right one show up at all*, and *was it near the top?*
- **Recall@k** — did the correct finding appear in the top *k* results? Recall@5 = 0.8 means "80% of the time the right finding was in my top 5." (Here "recall" = did we retrieve it; you pick k.)
- **MRR (Mean Reciprocal Rank)** — reward for ranking the right one high. If the correct hit is at position 1 you score 1.0, position 2 → 0.5, position 4 → 0.25, then average across all cases. High MRR = the right answer is usually at the top, not buried at rank 9.

**Why it matters:** If retrieval doesn't surface the relevant prior bug, nothing downstream can save you — the blackhat step is reasoning without the clue. Recall@k tells you if the info is *there*; MRR tells you if it's *usable* (a human reads the top 2-3, not the top 10).

**In your agent:** `rag/query.py` returns findings with similarity scores. For each benchmark case, check whether `canonical_finding_id` is in the top-k and at what rank.

**Interview angle:** "I separated retrieval quality from end-to-end quality, because when detection failed I needed to know whether it was a *retrieval* miss or a *reasoning* miss. Recall@10 was 0.9 but MRR was only 0.6, so the info was there but ranked too low — I fixed it in the ranking, not the model."

---

## 4. Detection metrics — precision, recall, and false positives

**What:** For the end-to-end system, three numbers that are always in tension:
- **Recall (detection rate)** — of all the real bugs, what fraction did you catch? Miss bugs → low recall.
- **Precision** — of everything you flagged, what fraction were real? Cry wolf → low precision.
- **False-positive rate** — of the *clean* contracts, how many did you wrongly flag? This is the one auditors care about most, because a tool that screams on everything is useless.

The tension: you can catch every bug by flagging *everything* (recall 1.0, precision terrible), or flag nothing risky (precision high, recall terrible). The skill is balancing them for your use case.

**Why it matters:** "Detection rate" alone is a vanity number — a tool that flags every line has 100% detection and zero value. Reporting precision + FP rate alongside it proves you understand the tradeoff. This is the difference between a toy and a tool.

**In your agent:** Detection rate = fraction of vulnerable benchmark contracts where the predicted `vuln_class` matched. FP rate = fraction of your clean contracts that got flagged. For an audit *assistant*, you'd bias toward recall (better to over-flag for a human to triage than miss a bug) — but you should *say* that's a deliberate choice.

**Interview angle:** "I tuned for high recall because it's an assistant, not an autonomous auditor — a human triages the output, so a missed bug costs more than a false alarm. My FP rate was 0.10, which I judged acceptable for that workflow." Owning the tradeoff *out loud* is the whole game.

---

## 5. Classification accuracy (getting the *kind* and *severity* right)

**What:** Catching that "something's wrong" is weaker than naming *what* is wrong. Severity accuracy and vuln-class accuracy measure whether you labeled it correctly, not just that you flagged it. This is multi-class (reentrancy vs rounding vs oracle-staleness…), not just yes/no.

**Why it matters:** In auditing, misclassifying a High as a Low, or calling a rounding bug an access-control bug, is a real error even though you "detected something." It shows whether the agent *understands* the bug or just pattern-matched a keyword.

**In your agent:** Compare predicted `severity` and `vuln_class` against the label, but only on cases you actually detected (don't punish severity on bugs you missed — that's already counted in recall).

**Interview angle:** "I measured detection and classification separately, because flagging the right line for the wrong reason is a silent failure I wanted visible."

---

## 6. Trajectory / step-level evals (the agentic differentiator)

**What:** Everything above scores the *final output*. A trajectory eval scores the *steps in between*. Your agent goes retrieve → blackhat reasoning → fuzz → synthesis. A trajectory eval asks at each stage: did retrieval find the pattern? did blackhat name the real attack path? did the fuzzer produce a counterexample? So when the final verdict is wrong, you know *which stage* broke.

**Why it matters:** This is *the* concept that separates people who've shipped agents from people who've built demos. Final-output-only evals can't tell you why an agent failed. Step-level evals can. The research I based your plan on said it plainly: if someone talks about agents but never mentions trajectory evals, they've never shipped one.

**In your agent:** Log each stage's output per case, and score them independently. Report a per-stage success rate: "retrieval 0.9, blackhat reasoning 0.7, synthesis 0.8" tells you blackhat is your weak link.

**Interview angle:** "I evaluate the trajectory, not just the verdict — retrieval succeeded 90% of the time but my reasoning step was the bottleneck at 70%, so that's where I focused." This is a top-1% junior answer. Rehearse it.

---

## 7. Observability & tracing

**What:** Observability is being able to *see inside* a run after it happened — the exact prompt, the retrieved chunks, the model's reasoning, timings — usually as a "trace" (a tree of timed steps called spans). Tools: Arize Phoenix (free, open-source), Braintrust, LangSmith.

**Why it matters:** Evals tell you *that* something's failing; traces tell you *why*. You'll spend most of your debugging time reading traces of failed cases. It's also a direct interview question: "how do you trace a failing agent trajectory?" — you want a fast, opinionated answer, not a shrug.

**In your agent:** Log retrieve/blackhat/fuzz/synthesis as spans of one trace per benchmark case. Even a JSONL file per run + a tiny viewer counts; Phoenix just makes it nicer and gives you a screenshot for the README.

**Interview angle:** "Phoenix, self-hosted — I traced every benchmark run so I could open a failed case and see whether it was retrieval or reasoning." Opinionated + specific = credible.

---

## 8. Cost, latency & regression (why you re-run)

**What:** Three practical numbers. **Cost** = dollars per contract (tokens × price). **Latency** = seconds per contract. **Regression testing** = re-running the whole benchmark after every change to make sure you didn't break something you'd fixed.

**Why it matters:** "Most engineers can build a working RAG; very few can cut a production bill in half while keeping quality flat" — that's a named, scarce, premium skill in 2026. Tracking cost lets you *demonstrate* it: "I routed pass-1 to a cheaper model and cut cost 42% with detection flat." Regression testing is why the benchmark is *fixed and repeatable* — a metric you can't re-run is a metric you can't trust.

**In your agent:** Sum embedding + LLM tokens per case → cost. Time each case → latency. Keep the benchmark stable so numbers are comparable across runs; commit `results/report.md` each time.

**Interview angle:** "I tracked cost per audit and did one deliberate optimization — cheaper model on the cheap stage — and proved with the benchmark that quality held. And every prompt change got re-run against the full set before I trusted it."

---

## The one-hour path

Read all eight. Then, before you write any code, say each of these out loud in one sentence: *Recall@k, MRR, detection rate, precision, false-positive rate, trajectory eval, trace, cost regression.* If you can explain why each exists without looking, you understand evals well enough to build — and to interview. Then open `EVALS_SPEC.md` and start with the 8-case benchmark. You'll learn the last 20% by watching your own agent fail, which is the only way anyone really learns it.
