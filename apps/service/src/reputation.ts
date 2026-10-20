import { type CheckResult, type AnalysisStats, type ReputationResult } from "./types.ts";

const VIRUSTOTAL_API_ROOT = process.env.VIRUSTOTAL_API_ROOT

function isRecord(value: unknown): value is Record<string, unknown> { // {...: ...}
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype // check if value is Javascript Object
  );
}

function readStat(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function getApiKey(apiKey: string | undefined): string | undefined {
  const trimmed = apiKey?.trim();
  return trimmed ? trimmed : undefined;
}

function resultForStatus(status: number): ReputationResult {
  if (status === 401 || status === 403) return { status: "authentication-failed", message: "VirusTotal rejected the API key. Check VIRUSTOTAL_API_KEY and its access." };
  if (status === 404) return { status: "no-report", message: "VirusTotal has no domain report for this hostname." };
  if (status === 429) return { status: "rate-limited", message: "VirusTotal rate limit reached. Wait before trying again." };
  return { status: "api-error", message: `VirusTotal returned HTTP ${status}.` };
}

function headers(apiKey: string): HeadersInit {
  return { accept: "application/json", "x-apikey": apiKey };
}

function removeProtocol(domain: string): string {
  if (!domain.includes("https://", 0)) return domain;
  return domain.substring(8)
}

export async function lookupDomainReputation(domain: string, apiKey: string | undefined): Promise<ReputationResult> {
  const key = getApiKey(apiKey);
  if (!key) return { status: "not-configured", message: "VirusTotal reputation lookup was not run because VIRUSTOTAL_API_KEY is not configured." };

  domain = removeProtocol(domain) // temporary fix
  
  let response: Response;
  try {
    response = await fetch(`${VIRUSTOTAL_API_ROOT}/domains/${encodeURIComponent(domain)}`, { headers: headers(key) });  
  } catch {
    return { status: "network-error", message: "Could not reach VirusTotal. Check the network connection and try again." };
  }
  
  let payload: unknown;
  try {
    payload = await response.json(); 
  } catch {
    return { status: "malformed-response", message: "VirusTotal returned invalid JSON." };
  }
  if (!response.ok) { 
    const errorResult = resultForStatus(response.status)
    errorResult.message += `Response body: ${JSON.stringify(payload)}`
    return errorResult
  } 
  if (!isRecord(payload) || !isRecord(payload.data) || !isRecord(payload.data.attributes)) {
    return { status: "malformed-response", message: "VirusTotal returned an unexpected domain report." };
  }
  const attributes = payload.data.attributes;
  const rawStats = attributes.last_analysis_stats;
  if (!isRecord(rawStats)) { // rawStats ==== undefined will return malformed-response.
    return { status: "malformed-response", message: "VirusTotal returned invalid analysis statistics." };
  }
  const stats: AnalysisStats = {
    malicious: readStat(rawStats.malicious), suspicious: readStat(rawStats.suspicious),
    harmless: readStat(rawStats.harmless), undetected: readStat(rawStats.undetected),
  };
  const lastAnalysisAt = typeof attributes.last_analysis_date === "number" ? new Date(attributes.last_analysis_date * 1_000).toISOString() : undefined;

  return { status: "success", domain, stats, lastAnalysisAt, reportUrl: `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`, message: "VirusTotal domain report retrieved." };
}

export async function checkVirusTotalKey(apiKey: string | undefined): Promise<CheckResult> {
  const key = getApiKey(apiKey);
  if (!key) return { status: "not-configured", message: "VIRUSTOTAL_API_KEY is not configured." };
  let response: Response;
  try {
    response = await fetch(`${VIRUSTOTAL_API_ROOT}/metadata`, { headers: headers(key)});   // https://www.virustotal.com/api/v3/metadata
  } catch {
    return { status: "network-error", message: "Could not reach VirusTotal. Check the network connection and try again." };
  }
  if (response.ok) return { status: "success", message: "VirusTotal API key is accepted." };
  const error = resultForStatus(response.status);
  return { status: error.status === "no-report" ? "api-error" : error.status, message: error.message }; // error.status === "no-report" ? "api-error" : error.status this is because this endpoint is not returning 404 never
}
