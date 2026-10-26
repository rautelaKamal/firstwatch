/**
 * Split the output of one combined command into the three evidence files the
 * parser reads:
 *
 *   cat /etc/os-release; php -v; dpkg -l 'php*' 'libapache2-mod-php*'
 *
 * Pure and browser-safe, so the page can show what it detected as you paste.
 */

export const RUNTIME_COMMAND = "cat /etc/os-release; php -v; dpkg -l 'php*' 'libapache2-mod-php*'";

const OS_KEY = /^(NAME|VERSION|ID|ID_LIKE|VERSION_ID|VERSION_CODENAME|PRETTY_NAME|HOME_URL|SUPPORT_URL|BUG_REPORT_URL|PRIVACY_POLICY_URL|UBUNTU_CODENAME|LOGO|BUILD_ID|VARIANT|VARIANT_ID|DEBIAN_[A-Z_]+)=/;
const PHP_V = /^PHP \d+\.\d+/;
const PHP_V_TAIL = /^(Zend Engine|Copyright|\s+with )/;
const DPKG = /^(Desired=|\| Status=|\|\/ Err|\|\|\/ Name|\+\+\+-|(?:ii|hi|rc|iU|iF|iH|un|pn)\s+\S)/;

export type RuntimeParts = { "os-release": string; "php-v.txt": string; "dpkg.txt": string };

export function splitRuntime(text: string): RuntimeParts & { packages: number } {
  const os: string[] = [];
  const php: string[] = [];
  const dpkg: string[] = [];
  let inPhp = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+$/, "");
    if (OS_KEY.test(line)) {
      os.push(line);
      inPhp = false;
    } else if (PHP_V.test(line)) {
      php.push(line);
      inPhp = true;
    } else if (inPhp && PHP_V_TAIL.test(line)) {
      php.push(line);
    } else if (DPKG.test(line)) {
      dpkg.push(line);
      inPhp = false;
    } else {
      inPhp = false;
    }
  }
  return {
    "os-release": os.join("\n"),
    "php-v.txt": php.join("\n"),
    "dpkg.txt": dpkg.join("\n"),
    packages: dpkg.filter((l) => /^(ii|hi|iU|iF|iH)\s+\S*php/i.test(l)).length,
  };
}
