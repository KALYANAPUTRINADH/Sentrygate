import { reconcileFirewall as reconcileWindowsFirewall } from "./windows-firewall.js";
import { reconcileLinuxNftables } from "./linux-firewall.js";

export async function reconcilePlatformFirewall(rules, options = {}) {
  if (process.platform === "win32") return reconcileWindowsFirewall(rules, options);
  if (process.platform === "linux") return reconcileLinuxNftables(rules, options);
  if (process.platform === "darwin") throw new Error("macOS inbound IP firewall enforcement is unsupported; preview mode only");
  throw new Error(`Firewall management is unsupported on ${process.platform}`);
}
