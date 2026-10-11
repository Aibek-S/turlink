function inspectLink(input: string): { url: URL | null; warnings: string[]; error?: string } {
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

  if (url.protocol === "http:") {
    warnings.push("Uses an unencrypted HTTP connection");
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(url.hostname)) {
    warnings.push("Uses an IP address instead of a domain name");
  }
  if (url.hostname.includes("xn--")) {
    warnings.push("Contains an internationalized domain label that may imitate another domain");
  }

  if (url.username || url.password) {
    warnings.push("Contains credentials before the hostname, which can disguise the destination");
  }

  return { url, warnings };
}

function main(args: string[]): number {
  if (args.length !== 1 || args[0] === "--help" || args[0] === "-h") {
    console.log("Usage: npm run dev -- <url>");
    console.log("Checks a URL for a few visible warning signs. This is not a reputation or malware scan.");
    return args.length === 1 ? 0 : 2;
  }

  const result = inspectLink(args[0]);
  if (result.error) {
    console.error(`Could not check link: ${result.error}`);
    return 2;
  }

  console.log(`URL: ${result.url!.href}`);
  console.log(`Host: ${result.url!.hostname}`);
  if (result.warnings.length === 0) {
    console.log("No basic warning signs detected. This does not guarantee the link is safe.");
  } else {
    console.log("Warnings:");
    for (const warning of result.warnings) console.log(`- ${warning}`);
    console.log("A warning is not proof that the link is malicious.");
  }

  return 0;
}

process.exitCode = main(process.argv.slice(2));
