# FirstWatch

Every verdict is capped by what the evidence can prove. It can't be talked into reassuring you.

Package scanners tell you what to upgrade. FirstWatch reads the advisory and tells you why you're exposed, what partially protects you, and proves every claim. It reads what is actually installed, checks every PHP package against the distribution's own fix records, and shows why each verdict stands.

**Live demo:** https://firstwatch-xi.vercel.app

## The problem

A version-string check sees `PHP 8.1.2` or `PHP 8.4.27`, compares it to a CVE's affected range, and reports a verdict for the whole host. Banner-based scans and quick `php -v` checks work this way. During PHP2Shell (CVE-2026-109618 and CVE-2026-109619, disclosed 21 October 2026, CVSS 4.0 9.2), that approach is wrong in both directions:

- **False alarm.** Ubuntu 22.04 ships `php8.1 8.1.2-1ubuntu2.28`, which carries a backported fix. Upstream 8.1 is end of life with no fixed release, so the check reads "8.1, in range" and raises a critical alarm on a patched host.
- **False safety.** Debian splits PHP into packages. If `php8.4-fpm` is on `apt-mark hold`, an upgrade patches `php8.4-cli` but not FPM. `php -v` reports the patched CLI, so the check clears the host while the package serving traffic is still vulnerable.

### Why this matters

The two errors do not cost the same. A false alarm costs an engineer some time: they look, find the backport, and move on. False safety means nobody looks, and the server stays exposed until someone gets in.

That difference shapes the whole design. FirstWatch is allowed to be wrong in the cautious direction and is built never to be wrong in the reassuring one. Raising an alarm needs no evidence beyond a range match. Saying "Not affected" needs a specific, checkable record, and when that record is missing the answer falls back to "Unverified", not to "Not affected".

## Demo

Each link opens that case on the site as a recorded live run; no model is called.

| Case | Version-string check | Package-aware check | FirstWatch | What it shows |
|---|---|---|---|---|
| [Debian 13, FPM held back](https://firstwatch-xi.vercel.app/?example=g) (g) | Not affected | Affected | **Affected** | `php8.4-fpm` held at `8.4.16-1~deb13u1` while the CLI that `php -v` reports was patched to `8.4.27-1~deb13u1`. The version-string check clears the host; the FPM package is still vulnerable. |
| [Ubuntu 22.04, patched](https://firstwatch-xi.vercel.app/?example=a) (a) | Affected | Not affected | **Not affected** | Upstream 8.1 has no fixed release, but Ubuntu backported the fix into `8.1.2-1ubuntu2.28`. The version-string check raises a false alarm. |
| [Debian 12, no security pocket](https://firstwatch-xi.vercel.app/?example=e) (e) | Affected | Affected | **Affected** | All three agree, but FirstWatch names the packages, Debian's fixed version (`8.2.35-1~deb12u1`), and the exact `apt-get --only-upgrade` command, plus the missing `bookworm-security` line. |
| [Second CVE: Ubuntu 24.04](https://firstwatch-xi.vercel.app/?example=j) (j) | Affected | Not affected | **Not affected** | Second CVE (CVE-2024-11236): same pipeline, no code changes. Ubuntu backported the 8.3.14 fix into `8.3.6-0ubuntu0.24.04.3`. |
| [Dockerfile only](https://firstwatch-xi.vercel.app/?example=i) (i) | Affected | cannot express | **Unverified** | Only a floating `php:8.4-fpm` tag, no output from the server. FirstWatch abstains instead of guessing; the version-string check says Affected with nothing installed to back it. |

To check a real server, open [Check your own server](https://firstwatch-xi.vercel.app/?check): run one read-only command, paste its output, and press Check. The two code-only checks and parsing appear within seconds; the AI check follows and takes 2 to 4 minutes. It covers PHP2Shell on Ubuntu 22.04/24.04 and Debian 12/13. Anything else gets a "not supported yet" message and no verdict.

## How it works

1. **Parse the stack in code.** The output of `cat /etc/os-release; php -v; dpkg -l 'php*' 'libapache2-mod-php*'` gives every installed PHP package with its exact distro version, the distro release and its OSV ecosystem, the SAPI, and relevant ini settings. Each fact records whether it came from the running system or from a build file.
2. **Read the advisories once.** Both GitHub advisories (GHSA-w8hw and GHSA-6wmf) and the php.net announcement are fetched and cached. Affected and patched versions are parsed from the GHSA fields in code.
3. **Digest the prose, then verify it.** The model extracts SAPI statements, mitigations, settings to avoid, and backports, each with a quote. Code keeps only items whose quote appears verbatim on the page.
4. **Ask OSV about each exact package version.** `check_distro_fix` maps binary packages to the source package OSV indexes and asks whether that version is fixed, for each CVE.
5. **Let the model assemble the report.** It calls the tools and proposes one verdict per engine package per CVE, with citations.
6. **Enforce the invariants in code.** Eleven checks run after the model answers. Any verdict the evidence does not support is downgraded, and the reason is recorded.
7. **Annotate.** Citations are checked against the raw text of the source they name, settings the advisory warns against get a cited warning, and the patched versions of both CVEs are compared.
8. **Compare with two code-only baselines.** The version-string check reads the single version number a banner scan or `php -v` check would. The package-aware check compares each dpkg-installed engine package with the distribution's fix record in OSV, our own reimplementation of the approach package scanners take. Both are shown next to every verdict.

```
 stack files ──► parse_stack (code) ──► packages, distro, SAPI, ini
                                              │
 advisories ──► fetch once ──► GHSA fields (code) ───────┐
                    │                                    │
                    └──► prose digest (model) ──► quote check (code)
                                                         │
 OSV ◄── check_distro_fix (code) ◄── agent loop (model) ◄┘
                                         │
                                         ▼
                              proposed report (model)
                                         │
                                         ▼
                        11 invariants + annotate (code)
                                         │
                                         ▼
                    final report  ◄──►  version-string and package-aware checks (code)
```

### Why per package and per CVE

`php -v` describes only the CLI binary. The FPM process that serves web traffic is a separate package and can be on a different version. In case g, `php8.4-fpm` is on `apt-mark hold`, so an upgrade moved the CLI to `8.4.27-1~deb13u1` and left FPM at `8.4.16-1~deb13u1`. One verdict per host, read from `php -v`, says "patched". One verdict per package says FPM is still affected.

The same goes for CVEs. PHP2Shell is two CVEs, and a mitigation can reduce one without touching the other: `memory_limit=-1` reduces CVE-2026-109618 only. A single verdict for "PHP2Shell" would have to either ignore that mitigation or wrongly apply it to both. So every engine package gets a verdict for every CVE, and the host's overall verdict is the worst of them.

## The safety design: the model proposes, code decides

The model never has the last word on a verdict. After it answers, these invariants are enforced in code against a ledger of what the tools actually returned. They only make a verdict less reassuring, never more. Raising an alarm needs no permission; clearing a package does.

| | Invariant |
|---|---|
| I1 | NOT_AFFECTED requires an OSV-confirmed fix for this exact installed version in this stack's own ecosystem, or a code-computed out-of-range result. |
| I2 | AFFECTED_MITIGATED requires sourced evidence that the package is affected, plus a mitigation. |
| I3 | A verdict more reassuring than UNVERIFIED requires runtime evidence of this package's own installed version. |
| I4 | An inexact version cannot decide a range that splits inside its own branch. |
| I5 | A package's verdict must rest on that package's own installed version, never on another package's. |
| I6 | Every engine-carrying PHP package in the stack needs a verdict for every CVE under assessment. |
| I7 | A range may only clear a package if its boundary versions appear in something actually fetched this run. |
| I8 | A range clears a version only if no range places it inside, and the clearing range covers the version's own branch. |
| I9 | A finding must name a package that is in the parsed inventory. |
| I10 | A mitigation counts only if its quote appears in a fetched advisory, names the setting, and the stack actually sets it. |
| I11 | A finding must be about one of the CVEs under assessment, and evidence for one CVE never clears another. |

On the site, the **Safety ledger** panel shows this for every package and CVE: the evidence that let the verdict stand, or the rule that downgraded it and why. It opens by default on the held-FPM example.

`AFFECTED_MITIGATED` is shown as "Affected, exposure reduced": both advisories say no configuration is a complete fix.

The **what-if toggles** on the site use the same engine. Setting `memory_limit = -1` or an `RLIMIT_AS` limit re-evaluates a recorded run in code only, labelled "Re-evaluated by the safety engine · no model call". Ten runs of each toggle combination give byte-identical reports.

### Why the model proposes and code decides

A language model reads text as tokens. It does not compare `8.1.2-1ubuntu2.28` with `8.1.2-1ubuntu2.21` the way dpkg does, and it can state a fix or a range that no source contains. So the model never does version math and never has the final word. It reads, calls tools, and proposes. Code compares versions, checks each claim against the ledger of tool results, and decides the verdict.

The rules only move one way. They can turn "Not affected" into "Unverified" or "Affected", never the reverse. "Not affected" survives only if the ledger holds an OSV row saying this exact version is fixed in this stack's ecosystem, or a range check computed by code against a range that was actually fetched.

The checks themselves need the same care. An early version of the range rule cleared a package if `some` range result said "outside". Version 8.4.16 checked only against the 8.5 range (`>= 8.5.0, < 8.5.12`) is outside it, so a vulnerable 8.4 package would have been cleared. The rule now requires `every` range result to be outside, and at least one of those ranges to cover the version's own branch (8.4.0 for 8.4.16). A test pins that exact case.

### Why verify the digest instead of trusting it

The first digest asked the model to extract everything from the advisory, including the version ranges. It lost 3 of the 4 ranges. Ranges are the one thing a wrong answer cannot afford to get wrong, so the design changed:

- Structured fields (affected versions, patched versions, CVE id) are parsed from the GHSA page by code.
- The model only reads the prose: which SAPIs are exposed, mitigations, settings to avoid, backports.
- Every item it returns must carry a quote, and code keeps the item only if that quote appears verbatim in the fetched page.

Scored against a hand-made answer key, the digest finds 37 of 39 facts. The two misses are the `memory.max` mitigation in GHSA-w8hw and the note "There is no complete generic configuration mitigation" in GHSA-6wmf.

## How this compares to package-aware scanners

The version-string check shown next to each verdict stands for banner-based scans and quick `php -v` checks. It is not a stand-in for package-aware scanners.

Tools such as Trivy, Grype, debsecan and Ubuntu's `pro fix` already read installed packages and distribution fix data. They would likely flag the held-FPM case (g) and clear the backport case (a) correctly. FirstWatch does not claim to beat them at that.

What FirstWatch adds is reading the advisory itself:

- **The cause, with the exact fix.** A held package gets the unhold step; a missing security repository gets the apt line to add; both get the `apt-get --only-upgrade` command for the packages involved.
- **Mitigations per CVE.** A stated mitigation that the stack actually sets lowers a verdict to "Affected, exposure reduced". It never clears a package.
- **Anti-mitigations.** Settings the advisory warns against, such as `RLIMIT_AS` and `RLIMIT_DATA` caps, get a cited warning.
- **Every claim cited.** Each claim names its source, and quotes are checked against the fetched page.
- **Safety rules in code.** The invariants above decide what survives.

The page shows a **package-aware check** next to every verdict, labelled "dpkg + distro data, like Trivy or debsecan". It is our own reimplementation of that approach in code: each dpkg-installed engine package's version against the distribution's OSV fix record. It is not the output of Trivy, Grype, debsecan or `pro fix`. It has only two answers, Affected and Not affected, so where FirstWatch says "Affected, exposure reduced" or "Unverified", or where there is no dpkg-installed PHP to compare, it shows a dash with a short note. On the eval cases it agrees with FirstWatch wherever it can answer, which is what you would expect; the list above is what FirstWatch adds on top.

It is meant to work alongside those tools, not replace them: a package-aware scanner across the fleet, and FirstWatch when one disclosure needs a careful, explained answer for a host.

## Results

### Eval: FirstWatch vs two code-only baselines

Ten cases, each with ground truth verified against the live OSV API (`eval/ground-truth.md`). `npm run verify-truth` re-checks the PHP2Shell rows.

| Case | Expected | FirstWatch (live run) | Version-string check | Package-aware check |
|---|---|---|---|---|
| a. Ubuntu 22.04, patched | Not affected | Not affected | Affected (false alarm) | Not affected |
| b. Ubuntu 22.04, stale package | Affected | Affected | Affected | Affected |
| c. Ubuntu 24.04, patched | Not affected | Not affected | Affected (false alarm) | Not affected |
| d. Debian 12, security pocket | Not affected | Not affected | Not affected | Not affected |
| e. Debian 12, no security pocket | Affected | Affected | Affected | Affected |
| f. Official php:8.1 image | Affected | Affected | Affected | cannot express (no dpkg PHP) |
| g. Debian 13, FPM held back | Affected | Affected | **Not affected (unsafe)** | Affected |
| h. 8.4 with mitigations | Affected, exposure reduced | Affected, exposure reduced | Affected | cannot express (no dpkg PHP) |
| i. Dockerfile only | Unverified | Unverified | Affected (no evidence) | cannot express (no dpkg output) |
| j. Second CVE (CVE-2024-11236): same pipeline, no code changes | Not affected | Not affected | Affected (false alarm) | Not affected |

- **FirstWatch:** 10 of 10 correct, every case run live, with 0 unsafe verdicts and 0 downgrades. In case d the model left the overall verdict empty and code recomputed it from the per-package findings.
- **Package-aware check:** 7 of 7 exact where it can answer. It cannot express f, h and i, which have no dpkg-installed PHP.
- **Version-string check:** 4 of 10 exact, 1 acceptable (h), 3 false alarms (a, c, j), 1 unsafe (g), and 1 verdict with no evidence behind it (i).

**Second CVE (CVE-2024-11236): same pipeline, no code changes.** CVE-2024-11236 (GHSA-5hqh-c84r-qjcv, an integer overflow in the firebird and dblib quoters) is fixed upstream in 8.3.14. Ubuntu 24.04 backported the fix into `8.3.6-0ubuntu0.24.04.3` (USN-7153-1). The case runs through the same parser, OSV check, GHSA field parser and invariants with no code changes. Run live on 27 October 2026, it reached Not affected for both engine packages with 0 downgrades. Separately, without a model call, a "Not affected" report one package release older (`.2`) is forced to Affected by I1.

### Digest recall: 37 of 39

Scored against a hand-verified answer key (`eval/digest-answer-key.json`):

| Source | Recall | Missed |
|---|---|---|
| GHSA-w8hw-w9fx-j79w | 19 / 20 | the `memory.max` mitigation |
| GHSA-6wmf-4rv5-p3rp | 17 / 18 | the note "There is no complete generic configuration mitigation" |
| php.net announcement | 1 / 1 | |

Affected ranges, patched versions and CVE ids are parsed in code and scored 100%. No fact the key marks as not stated by a GHSA (php-cgi, CLI, 8.1, backports) is attributed to one.

### Tokens and time per live run

Model: `openai/gpt-oss-120b` on Groq's free tier (8,000 tokens per minute).

| Case | Agent tokens | Requests | Time |
|---|---|---|---|
| b | 12,629 | 3 | 128 s |
| e | 12,333 | 3 | 188 s |
| g | 12,612 | 3 | 189 s |
| a (deployed site check) | 12,362 | 3 | 130 s locally, about 2 min 20 s on Vercel |
| j (one CVE, two packages) | 6,677 | 3 | 65 s |
| i (no packages, abstains) | 7,634 | 2 | 64 s |
| c | 12,245 | 3 | 127 s |
| d | 12,017 | 3 | 134 s |

Building the three PHP2Shell advisory digests cost 13,618 tokens once, and GHSA-5hqh for case j cost 806; they are cached and shipped with the deploy. Earlier runs of f and h took about 17,000 tokens each, because they included a repair request that has since been removed.

## Limits and honest caveats

- **Built around one incident.** The site checks PHP2Shell only. Case j shows the pipeline handles a second CVE without code changes, but the site's own-server input path, banner wording and what-if toggles are still written for PHP2Shell.
- **Extension-level CVEs can over-alarm.** CVE-2024-11236 lives in the firebird and dblib extensions. FirstWatch judges the main PHP packages, so a host without those extensions installed may get a false alarm. It cannot produce false safety this way.
- **Four distro releases.** Ubuntu 22.04 and 24.04, Debian 12 and 13. Other distributions, and PHP not installed from distro packages, get "not supported yet" and no verdict on the own-server path.
- **Free-tier pacing.** Requests are paced to stay under 8,000 tokens per minute, so a live run takes 2 to 4 minutes, most of it waiting.
- **Replays vs live.** The site opens on recorded live runs, and replaying one makes no model call. Live runs are rate-limited on the deployed site.
- **Rebuilt evidence for early recordings.** The six earlier recordings saved only the report. Their evidence ledgers were rebuilt afterwards by re-running the same code tools (OSV, range checks); newer runs save their own.
- **The digest misses things.** Recall is 37 of 39, and a model reading prose can miss a mitigation.

## Running locally

```bash
npm install
cp .env.example .env.local   # then add your Groq key as GROQ_API_KEY
npm run dev                  # http://localhost:3000, replays need no key
```

```bash
npm test                     # invariant, pipeline and digest-recall tests, no model or network
npm run eval -- --dry        # fixtures and both code-only baselines, no model calls
npm run eval -- --case g     # one live case (uses tokens)
npm run verify-truth         # re-check the PHP2Shell ground truth against live OSV
```

Environment variables are documented in `.env.example`. Live runs on a deployment also need `LIVE_ENABLED=true`.

## Credits

Built by Kamal Singh Rautela.

Data: [OSV.dev](https://osv.dev), [NVD](https://nvd.nist.gov), [endoflife.date](https://endoflife.date), the [PHP security advisories on GitHub](https://github.com/php/php-src/security/advisories), and the [php.net announcement](https://www.php.net/archive/2026.php).

Model: `openai/gpt-oss-120b` via [Groq](https://groq.com). Built with Next.js, hosted on Vercel.

Built solo with [Claude Code](https://www.anthropic.com/claude-code) for implementation and [Alan](https://x.com/tryAlanAI) for critique, research verification, and adversarial review of the safety layer. Architecture, safety design, and evaluation decisions are mine.

License: see [LICENSE](LICENSE).
