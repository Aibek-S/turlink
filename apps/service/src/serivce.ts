import { inspectLink, type LinkInspection, normalizeDomain } from "./link-inspector.ts";
import { lookupDomainReputation, type AnalysisStats, type ReputationResult } from "./reputation.ts";

export interface DetectionResponse {
  linkInspection: LinkInspection;
  reputationResult?: ReputationResult
}

export type DetectionType = "complicated" | "notComplicated"//TODO make external file for all interfaces, dto.

/*function printUsage(): void {
  console.log("Usage: pnpm dev [--reputation] <url>");
  console.log("       pnpm dev --reputation-health");
  console.log("Checks a URL for visible warning signs. This is not a malware or safety guarantee.");
}

function printLocalResult(input: string): ReturnType<typeof inspectLink> {
  const result = inspectLink(input);
  if (result.error) {
    console.error(`Could not check link: ${result.error}`);
    return result;
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
  return result;
}

function valueOrUnavailable(value: number | null): string {
  return value === null ? "unavailable" : String(value);
}

function printStats(stats: AnalysisStats | undefined): void {
  if (!stats) {
    console.log("Analysis counts: unavailable in this VirusTotal report.");
    return;
  }
  console.log(`Analysis counts: malicious=${valueOrUnavailable(stats.malicious)}, suspicious=${valueOrUnavailable(stats.suspicious)}, harmless=${valueOrUnavailable(stats.harmless)}, undetected=${valueOrUnavailable(stats.undetected)}`);
  if (stats.malicious !== null && stats.suspicious !== null) {
    if (stats.malicious > 0 || stats.suspicious > 0) console.log("VirusTotal reports positive malicious or suspicious detections. Review the report before making a decision.");
    else console.log("VirusTotal reports no malicious or suspicious detections. This does not prove the domain is safe.");
  }
}

function printReputationResult(result: ReputationResult): void {
  console.log(`VirusTotal: ${result.message}`);
  if (result.status !== "success") return;
  printStats(result.stats);
  if (result.lastAnalysisAt) console.log(`Last analysis: ${result.lastAnalysisAt}`);
  if (result.reportUrl) console.log(`Report: ${result.reportUrl}`);
}*/
export function outerNormalize(linkInspection: LinkInspection, reputationResult?: ReputationResult): DetectionResponse {
  return {
    linkInspection: linkInspection,
    reputationResult: reputationResult
  }
}
export async function main(domainName: string, detectionType: DetectionType): Promise<DetectionResponse> {
  /*if (args.length === 1 && args[0] === "--reputation-health") {
    console.log("VirusTotal key check contacts VirusTotal but does not submit a domain.");
    const result = await checkVirusTotalKey(process.env.VIRUSTOTAL_API_KEY);
    console.log(`VirusTotal: ${result.message}`);
    return result.status === "success" ? 0 : 2;
  }*/ // check for api key health just, do we need this?
  /*const reputation = args.includes("--reputation");
  const values = args.filter((argument) => argument !== "--reputation");
  if (values.length !== 1 || values[0] === "--help" || values[0] === "-h") {
    printUsage();
    return values.length === 1 ? 0 : 2;
    }
  const result = printLocalResult(values[0]);
  if (result.error) return 2;
  if (!reputation) return 0;*/ // junk from cli
  const domain = normalizeDomain(domainName);
  if (detectionType == "notComplicated") {
    const inspectionResult = inspectLink(domain)
    return outerNormalize(inspectionResult)
  }
  else { // domain check
    const inspectionResult = inspectLink(domain)
    if (inspectionResult.error) {
      return outerNormalize(inspectionResult, {message: "Your request is inappropriate", status: "basic-inspection-exception"})
    }
    const reputationResult = await lookupDomainReputation(domain, process.env.VIRUSTOTAL_API_KEY)
    return outerNormalize(inspectionResult, reputationResult)
  }
}
// ATTENTION: ALL /**/ is lines of code from prev cli. it means this is just junk. you can delete if you are confident. 
