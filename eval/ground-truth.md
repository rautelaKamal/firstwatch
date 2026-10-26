# Ground truth: PHP2Shell (CVE-2026-109618, CVE-2026-109619)

Every row below was verified against the live OSV API on 2026-10-26, and the
verification is reproducible with `npm run verify-truth`. Do not edit an
expected verdict in `eval/cases/` without re-running that check first: if OSV
or a distro republishes, the answer key moves and the eval must move with it.

## The disclosure

| | |
|---|---|
| CVEs | CVE-2026-109618 (RCE via OOM corruption), CVE-2026-109619 (RCE via stale global state) |
| Disclosed | 2026-10-21 |
| Severity | CVSS 4.0 9.2 critical (`CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`) |
| Upstream advisories | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) |
| Upstream fixed releases | 8.2.35, 8.3.36, 8.4.27, 8.5.12 |
| NVD ranges | 109618: `>= 7.3.0 < 8.2.35`; 109619: `>= 5.4.0 < 8.2.35`; both also `>= 8.3.0 < 8.3.36`, `>= 8.4.0 < 8.4.27`, `>= 8.5.0 < 8.5.12` |

**No upstream release does not mean no fix.** Neither GHSA mentions 8.1 or
backports; the [php.net announcement](https://www.php.net/archive/2026.php)
does, and it is the source for every claim about them:

> "PHP 8.1 and older no longer receive updates from the PHP project. Some
> distributions and LTS vendors provide backported fixes, so contact your
> vendor for details, or upgrade to a supported version."

> "Given the severity of these vulnerabilities, the PHP security team provided
> minimal source-backports for PHP 7.4, PHP 8.0, and PHP 8.1 to help people
> building from source or without access to an LTS vendor."

So a version-string scanner reads "PHP 8.1, EOL, in range" and raises an alarm
that is wrong on Ubuntu 22.04 (packaged backport) and right on the upstream
`php:8.1-fpm` image (built from the 8.1.33 release, which has neither the
distro fix nor the source backport). That difference is the product.

The archive page also carries a separate entry for CVE-2026-115560, so the
digest narrows it to the paragraphs that mention this disclosure.

## Distro fixed versions, from OSV

Source: `https://api.osv.dev/v1/vulns/UBUNTU-CVE-2026-109618` and
`https://api.osv.dev/v1/vulns/DEBIAN-CVE-2026-109618`.

| OSV ecosystem | source package | fixed in |
|---|---|---|
| `Ubuntu:Pro:14.04:LTS` | php5 | `5.5.9+dfsg-1ubuntu4.29+esm18` |
| `Ubuntu:Pro:16.04:LTS` | php7.0 | `7.0.33-0ubuntu0.16.04.16+esm22` |
| `Ubuntu:Pro:18.04:LTS` | php7.2 | `7.2.24-0ubuntu0.18.04.17+esm14` |
| `Ubuntu:Pro:20.04:LTS` | php7.4 | `7.4.3-4ubuntu2.29+esm5` |
| `Ubuntu:22.04:LTS` | php8.1 | `8.1.2-1ubuntu2.28` |
| `Ubuntu:24.04:LTS` | php8.3 | `8.3.6-0ubuntu0.24.04.13` |
| `Ubuntu:26.04:LTS` | php8.5 | `8.5.4-0ubuntu1.5` |
| `Ubuntu:26.10` | php8.5 | `8.5.9-0ubuntu2.1` |
| `Debian:12` (bookworm, LTS, so DLA not DSA) | php8.2 | `8.2.35-1~deb12u1` |
| `Debian:13` (trixie) | php8.4 | `8.4.27-1~deb13u1` |
| `Debian:14` (forky) | php8.4 | `8.4.27-1` |

Distro advisories: [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1),
[USN-8948-2](https://ubuntu.com/security/notices/USN-8948-2),
[Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-109618),
[Ubuntu CVE page](https://ubuntu.com/security/CVE-2026-109618).

## Two facts that shape the implementation

1. **OSV indexes Debian and Ubuntu by source package.** Querying `php8.1-fpm`
   or `libapache2-mod-php8.1` returns zero vulnerabilities, which is
   indistinguishable from "patched" and is not the same thing. `check_distro_fix`
   maps binary to source (`php8.1-fpm` -> `php8.1`) before querying.
2. **A clean result is only meaningful if OSV holds the CVE for that
   ecosystem.** So the tool first fetches `UBUNTU-CVE-*`/`DEBIAN-CVE-*` and
   confirms it covers that ecosystem and source package. When it does not, the
   answer is `unknown`, never `fixed`. OSV has no record under the bare
   `CVE-2026-109618` id (only Bitnami `BIT-*` aliases), so the distro-prefixed
   id is the one to ask for. DSA, DLA and USN ids are not OSV ids and 404.

## Verified package verdicts

Checked with `check_distro_fix("CVE-2026-109618", ...)`, 14/14 matching.

| ecosystem | package | version | OSV verdict |
|---|---|---|---|
| Ubuntu:22.04:LTS | php8.1 | `8.1.2-1ubuntu2.28` | fixed |
| Ubuntu:22.04:LTS | php8.1-fpm | `8.1.2-1ubuntu2.28` | fixed (via source php8.1) |
| Ubuntu:22.04:LTS | libapache2-mod-php8.1 | `8.1.2-1ubuntu2.28` | fixed (via source php8.1) |
| Ubuntu:22.04:LTS | php8.1-fpm | `8.1.2-1ubuntu2.21` | affected |
| Ubuntu:24.04:LTS | php8.3-fpm | `8.3.6-0ubuntu0.24.04.13` | fixed |
| Ubuntu:24.04:LTS | php8.3-fpm | `8.3.6-0ubuntu0.24.04.5` | affected |
| Debian:12 | php8.2-fpm | `8.2.35-1~deb12u1` | fixed |
| Debian:12 | php8.2-fpm | `8.2.32-1~deb12u1` | affected |
| Debian:12 | php8.2-fpm | `8.2.28-1~deb12u1` | affected |
| Debian:13 | php8.4-cli | `8.4.27-1~deb13u1` | fixed |
| Debian:13 | php8.4-fpm | `8.4.16-1~deb13u1` | affected |
| Ubuntu:22.04:LTS | php-fpm (unversioned) | `8.1.2-1ubuntu2.28` | unknown, cannot map to a source package |
| Ubuntu:22.04:LTS | php8.1-fpm | `8.1.33` (upstream string) | unknown, not a distro version |
| Ubuntu:99.04 | php8.1-fpm | `8.1.2-1ubuntu2.28` | unknown, ecosystem not covered |

## Exploitation confidence, from the GHSA text

This annotates severity only. It never changes a verdict, and nothing with an
affected version is cleared because of its SAPI.

The digest stores each SAPI's status in the advisory's exact words, checked to
sit inside the quoted sentence, never a paraphrase.

| SAPI | confidence | the advisory's own words |
|---|---|---|
| Apache mod_php | confirmed | "The fatal backtrace path has confirmed RCE against mod_php." and "Apache mod_php unconditionally invokes the request shutdown procedure, even when request startup has failed." |
| PHP-FPM | presumed | "FPM is conditionally exposed when nginx, Apache `mod_proxy_fcgi` or another frontend sends `PHP_VALUE`/`PHP_ADMIN_VALUE` parameters that produce a diagnostic before request initialization." and "no complete FPM exploit has been demonstrated for this SAPI." |
| FrankenPHP | presumed | "calls the request shutdown procedure unconditionally, making it likely susceptible to application-independent attacks." |
| LiteSpeed (LSAPI) | presumed | "LSAPI models FPM, with application-specific exploits being likely but unvalidated." |
| php-cgi, CLI | unaddressed | Neither advisory mentions php-cgi or CLI. |

## Stated configuration mitigations

None is a complete fix, which is why `AFFECTED_MITIGATED` is displayed as
**"Affected, exposure reduced"**. GHSA-w8hw: "Updating to a PHP release
containing the patch to this vulnerability is the _only_ complete mitigation."
php.net: "while only an update is a complete solution, the following measures
reduce exposure to specific attack paths but do not make an installation safe."

- `memory_limit=-1` set administratively: "the primary configuration mitigation", and the advisory adds "This is not a complete mitigation."
- `session.upload_progress.enabled=0` administratively plus a worker restart.
- `fatal_error_backtraces=0` administratively, on 8.5, plus a worker restart.
- Keep `post_max_size` conservative and enforce decoded request size at the frontend.
- Do **not** use `RLIMIT_AS` or `RLIMIT_DATA`. This is an anti-mitigation:
  GHSA-w8hw says they "will cause `mmap()` to fail once the memory limit is
  reached", and php.net says "Do not substitute RLIMIT_AS or RLIMIT_DATA, as
  these can cause the vulnerable allocation failure." `parse_stack` detects
  them (`ulimit -v`/`-d`, systemd `LimitAS=`/`LimitDATA=`, `--ulimit as=`,
  compose `ulimits:`, pasted `ulimit -a`) and the report carries a cited
  warning when either is set.

## Expected verdicts per eval case

| case | expected | why |
|---|---|---|
| a-ubuntu2204-patched | `NOT_AFFECTED` | OSV: php8.1 `8.1.2-1ubuntu2.28` fixed. Scanner says EOL 8.1 and is wrong. |
| b-ubuntu2204-stale | `AFFECTED` | OSV: `8.1.2-1ubuntu2.21` affected, fix in `8.1.2-1ubuntu2.28` via apt. |
| c-ubuntu2404-patched | `NOT_AFFECTED` | OSV: php8.3 `8.3.6-0ubuntu0.24.04.13` fixed. |
| d-debian12-security-pocket | `NOT_AFFECTED` | OSV: php8.2 `8.2.35-1~deb12u1` fixed. |
| e-debian12-no-security-pocket | `AFFECTED` | OSV: `8.2.32-1~deb12u1` affected, fix exists in bookworm-security. Hero case. |
| f-upstream-php81-fpm-image | `AFFECTED` | Upstream image, no 8.1 release exists, EOL. Isolate or move branch. |
| g-split-cli-patched-fpm-stale | `AFFECTED` | php8.4-cli `8.4.27-1~deb13u1` fixed but php8.4-fpm `8.4.16-1~deb13u1` affected. Per package. |
| h-upstream-84-mitigated | `AFFECTED_MITIGATED` | Upstream 8.4.12 in range; `session.upload_progress.enabled=0` and `memory_limit=-1` are stated mitigations, not fixes. |
| i-dockerfile-only | `UNVERIFIED` | Floating `php:8.4-fpm` tag, no runtime evidence. Nothing can be concluded. |
