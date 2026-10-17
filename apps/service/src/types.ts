export interface DetectBodyDto  {
  url: string;
  complicated?: boolean;
}

export interface DetectionResponse {
  linkInspection: LinkInspection;
  reputationResult?: ReputationResult
}

export type DetectionType = "complicated" | "notComplicated"//TODO make external file for all interfaces, dto.

export interface LinkInspection {
  url: URL | null;
  warnings: string[];
  error?: string;
}

export type ReputationStatus = "success" | "not-configured" | "authentication-failed" | "no-report" | "rate-limited" | "network-error" | "malformed-response" | "api-error" | "basic-inspection-exception";

export interface AnalysisStats {
  malicious: number | null;
  suspicious: number | null;
  harmless: number | null;
  undetected: number | null;
}

export interface ReputationResult {
  status: ReputationStatus;
  domain?: string;
  stats?: AnalysisStats;
  lastAnalysisAt?: string;
  reportUrl?: string;
  message: string;
}

export interface CheckResult {
  status: ReputationStatus;
  message: string
}