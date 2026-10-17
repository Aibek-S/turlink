import type { DetectionResponse, DetectionType, LinkInspection, ReputationResult } from "./types.ts";
import { basicInspection, normalizeDomain } from "./basic-inspector.ts";
import { lookupDomainReputation} from "./reputation.ts";

export function outerNormalize(linkInspection: LinkInspection, reputationResult?: ReputationResult): DetectionResponse {
  return {
    linkInspection: linkInspection,
    reputationResult: reputationResult
  }
}

export async function inspection(domainName: string, detectionType: DetectionType): Promise<DetectionResponse> {
  const domain = normalizeDomain(domainName);
  if (detectionType == "complicated") {
    const inspectionResult = basicInspection(domain)
    if (inspectionResult.error) {
      return outerNormalize(inspectionResult, {message: "Your request is inappropriate", status: "basic-inspection-exception"})
    }
    const reputationResult = await lookupDomainReputation(domain, process.env.VIRUSTOTAL_API_KEY)
    return outerNormalize(inspectionResult, reputationResult)
  }
  else { // undefined or notComplicated
    const inspectionResult = basicInspection(domain)
    return outerNormalize(inspectionResult)
  }
}
