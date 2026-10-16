import type { DetectionResponse, DetectionType, LinkInspection, ReputationResult } from "./types.ts";
import { inspectLink, normalizeDomain } from "./link-inspector.ts";
import { lookupDomainReputation} from "./reputation.ts";

export function outerNormalize(linkInspection: LinkInspection, reputationResult?: ReputationResult): DetectionResponse {
  return {
    linkInspection: linkInspection,
    reputationResult: reputationResult
  }
}
export async function main(domainName: string, detectionType: DetectionType): Promise<DetectionResponse> {
  
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
