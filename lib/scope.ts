/**
 * What "check your own server" covers. Pure and browser-safe, so the page and
 * the route apply the same rule: outside this scope there is a message, never
 * a verdict.
 */

import { splitRuntime } from "./runtime";

export const SCOPE_LINE = "Checks PHP2Shell (CVE-2026-109618, CVE-2026-109619) on Ubuntu 22.04/24.04 and Debian 12/13.";

const SUPPORTED: Record<string, string> = {
  "ubuntu 22.04": "Ubuntu 22.04", "ubuntu 24.04": "Ubuntu 24.04", "debian 12": "Debian 12", "debian 13": "Debian 13",
};
// Debian testing and some minimal images leave out VERSION_ID; the codename still says which release it is.
const CODENAMES: Record<string, string> = { jammy: "ubuntu 22.04", noble: "ubuntu 24.04", bookworm: "debian 12", trixie: "debian 13" };

export type Scope = { ok: true; distro: string } | { ok: false; message: string };

const field = (os: string, key: string) => os.match(new RegExp(`^${key}=["']?([^"'\\n]*)`, "m"))?.[1]?.trim() ?? "";

/** Is this pasted output something the check covers? */
export function checkScope(text: string): Scope {
  const parts = splitRuntime(text);
  const os = parts["os-release"];
  if (!os) {
    return { ok: false, message: "No /etc/os-release in the output, so the distribution is unknown. Run the whole command and paste all of its output." };
  }
  const id = field(os, "ID").toLowerCase();
  const key = `${id} ${field(os, "VERSION_ID")}`;
  const distro = SUPPORTED[key] ?? SUPPORTED[CODENAMES[field(os, "VERSION_CODENAME").toLowerCase()] ?? ""];
  if (!distro) {
    const name = field(os, "PRETTY_NAME") || key.trim() || "this distribution";
    return { ok: false, message: `Not supported yet: ${name}. FirstWatch checks Ubuntu 22.04/24.04 and Debian 12/13 for now, so no verdict is given.` };
  }
  if (!parts.packages) {
    return {
      ok: false,
      message: `Not supported yet: dpkg lists no installed PHP packages on this ${distro} host. The check reads PHP from the distribution's packages; PHP built from source or from an official php Docker image is not covered yet, so no verdict is given.`,
    };
  }
  return { ok: true, distro };
}
