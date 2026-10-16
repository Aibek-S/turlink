import { type LinkInspection } from "./types.ts";

export function inspectLink(input: string): LinkInspection {
  let url: URL;

  try {
    url = new URL(input);
  } catch {
    return { url: null, warnings: [], error: "Invalid URL. Include a scheme, for example https://example.com" };
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { url, warnings: [], error: `Unsupported protocol: ${url.protocol}` };
  }

  const warnings: string[] = [];
  if (url.protocol === "http:") warnings.push("Uses an unencrypted HTTP connection");
  if (isIpAddress(url.hostname)) warnings.push("Uses an IP address instead of a domain name");
  if (url.hostname.includes("xn--")) warnings.push("Contains an internationalized domain label that may imitate another domain");
  if (url.username || url.password) warnings.push("Contains credentials before the hostname, which can disguise the destination");

  return { url, warnings };
}

export function isIpAddress(hostname: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname) || hostname.includes(":");
}

export function normalizeDomain(hostname: string): string {
  return hostname.trim().replace(/\.$/, "");
}
