# FirstWatch

> DRAFT. Sections marked `TODO(Kamal)` are for the author to write.

Version scanners read one version string. FirstWatch reads what is actually installed, checks every PHP package against the distribution's own fix records, and shows why each verdict stands.

**Live demo:** https://firstwatch-xi.vercel.app

## The problem

A version scanner sees `PHP 8.1.2` or `PHP 8.4.27`, compares it to a CVE's affected range, and reports a verdict for the whole host. During PHP2Shell (CVE-2026-109618 and CVE-2026-109619, disclosed 21 October 2026, CVSS 4.0 9.2), that approach is wrong in both directions:

- **False alarm.** Ubuntu 22.04 ships `php8.1 8.1.2-1ubuntu2.28`, which carries a backported fix. Upstream 8.1 is end of life with no fixed release, so a scanner reads "8.1, in range" and raises a critical alarm on a patched host.
- **False safety.** Debian splits PHP into packages. If `php8.4-fpm` is on `apt-mark hold`, an upgrade patches `php8.4-cli` but not FPM. `php -v` reports the patched CLI, so a scanner clears the host while the package serving traffic is still vulnerable.

### Why this matters

TODO(Kamal): explain in your own words.

## Demo

Each example opens on the site as a recorded live run. One click replays it; no model is called.

| Case | Version scanner | FirstWatch | What it shows |
|---|---|---|---|
| [Debian 13, FPM held back](https://firstwatch-xi.vercel.app) (g) | Not affected | **Affected** | `php8.4-fpm` held at `8.4.16-1~deb13u1` while the CLI that `php -v` reports was patched to `8.4.27-1~deb13u1`. The scanner clears the host; the FPM package is still vulnerable. |
| [Ubuntu 22.04, patched](https://firstwatch-xi.vercel.app) (a) | Affected | **Not affected** | Upstream 8.1 has no fixed release, but Ubuntu backported the fix into `8.1.2-1ubuntu2.28`. The scanner raises a false alarm. |
| [Debian 12, no security pocket](https://firstwatch-xi.vercel.app) (e) | Affected | **Affected** | Both agree, but FirstWatch names the packages, Debian's fixed version (`8.2.35-1~deb12u1`), and the exact `apt-get --only-upgrade` command, plus the missing `bookworm-security` line. |

TODO(Kamal): the three links all open the site, which loads case (g) by default. Decide whether to add per-example links.

## How it works

1. **Parse the stack in code.** The output of `cat /etc/os-release; php -v; dpkg -l 'php*' 'libapache2-mod-php*'` gives every installed PHP package with its exact distro version, the distro release and its OSV ecosystem, the SAPI, and relevant ini settings. Each fact records whether it came from the running system or from a build file.
2. **Read the advisories once.** Both GitHub advisories (GHSA-w8hw and GHSA-6wmf) and the php.net announcement are fetched and cached. Affected and patched versions are parsed from the GHSA fields in code.
3. **Digest the prose, then verify it.** The model extracts SAPI statements, mitigations, settings to avoid, and backports, each with a quote. Code keeps only items whose quote appears verbatim on the page.
4. **Ask OSV about each exact package version.** `check_distro_fix` maps binary packages to the source package OSV indexes and asks whether that version is fixed, for each CVE.
5. **Let the model assemble the report.** It calls the tools and proposes one verdict per engine package per CVE, with citations.
6. **Enforce the invariants in code.** Eleven checks run after the model answers. Any verdict the evidence does not support is downgraded, and the reason is recorded.
7. **Annotate.** Citations are checked against the raw text of the source they name, settings the advisory warns against get a cited warning, and the patched versions of both CVEs are compared.
8. **Compare with a version scanner.** A deterministic baseline reads the single version string a scanner would, and is shown next to every verdict.

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
                    final report  ◄──►  scanner baseline (code)
```

### Why per package and per CVE

TODO(Kamal): explain in your own words.

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

`AFFECTED_MITIGATED` is shown as "Affected, exposure reduced": both advisories say no configuration is a complete fix.

The **what-if toggles** on the site use the same engine. Setting `memory_limit = -1` or an `RLIMIT_AS` limit re-evaluates a recorded run in code only, labelled "Re-evaluated by the safety engine · no model call". Ten runs of each toggle combination give byte-identical reports.

### Why the model proposes and code decides

TODO(Kamal): explain in your own words.

### Why verify the digest instead of trusting it

TODO(Kamal): explain in your own words.

## Results

### Eval: FirstWatch vs a version scanner

Nine cases, each with ground truth verified against the live OSV API (`eval/ground-truth.md`, re-checked by `npm run verify-truth`).

| Case | Expected | FirstWatch (live run) | Version scanner |
|---|---|---|---|
| a. Ubuntu 22.04, patched | Not affected | Not affected | Affected (false alarm) |
| b. Ubuntu 22.04, stale package | Affected | Affected | Affected |
| c. Ubuntu 24.04, patched | Not affected | not yet run live | Affected (false alarm) |
| d. Debian 12, security pocket | Not affected | not yet run live | Not affected |
| e. Debian 12, no security pocket | Affected | Affected | Affected |
| f. Official php:8.1 image | Affected | Affected | Affected |
| g. Debian 13, FPM held back | Affected | Affected | **Not affected (unsafe)** |
| h. 8.4 with mitigations | Affected, exposure reduced | Affected, exposure reduced | Affected |
| i. Dockerfile only | Unverified | not yet run live | Affected (no evidence) |

- **FirstWatch:** 6 of 6 cases run live are correct, with 0 unsafe verdicts and 0 downgrades.
- **Scanner:** 4 of 9 exact, 1 acceptable (h), 2 false alarms (a, c), 1 unsafe (g), and 1 verdict with no evidence behind it (i).

TODO(Kamal): run c, d and i live and fill in the column, or keep them marked as not run.

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

Building the three advisory digests cost 13,618 tokens once; they are cached and shipped with the deploy. Earlier runs of f and h took about 17,000 tokens each, because they included a repair request that has since been removed.

## Limits and honest caveats

- **One incident.** Everything here is built and tested around PHP2Shell on Debian and Ubuntu. The approach is general; the coverage is not.
- **Free-tier pacing.** Requests are paced to stay under 8,000 tokens per minute, so a live run takes 2 to 4 minutes, most of it waiting.
- **Replays vs live.** The site opens on recorded live runs, and replaying one makes no model call. Live runs are rate-limited on the deployed site. The evidence ledgers for the six earlier recordings were rebuilt afterwards by re-running the same code tools (OSV, range checks), because those runs saved only the report.
- **Not every case is run live.** c, d and i have ground truth and a scanner baseline, but no live FirstWatch run under the current design.
- **The digest misses things.** Recall is 37 of 39, and a model reading prose can miss a mitigation.

TODO(Kamal): add anything you would want a judge to know before they trust a verdict.

## Running locally

```bash
npm install
cp .env.example .env.local   # then add your Groq key as GROQ_API_KEY
npm run dev                  # http://localhost:3000, replays need no key
```

```bash
npm test                     # invariant, pipeline and digest-recall tests, no model or network
npm run eval -- --dry        # fixtures and scanner baseline, no model calls
npm run eval -- --case g     # one live case (uses tokens)
npm run verify-truth         # re-check the ground truth against live OSV
```

Environment variables are documented in `.env.example`. Live runs on a deployment also need `LIVE_ENABLED=true`.

## Credits

Built by Kamal Singh Rautela.

Data: [OSV.dev](https://osv.dev), [NVD](https://nvd.nist.gov), [endoflife.date](https://endoflife.date), the [PHP security advisories on GitHub](https://github.com/php/php-src/security/advisories), and the [php.net announcement](https://www.php.net/archive/2026.php).

Model: `openai/gpt-oss-120b` via [Groq](https://groq.com). Built with Next.js, hosted on Vercel.

TODO(Kamal): acknowledgements.

License: see [LICENSE](LICENSE).
