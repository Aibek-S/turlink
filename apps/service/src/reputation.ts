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

export type FetchLike = typeof fetch;
const VIRUSTOTAL_API_ROOT = process.env.VIRUSTOTAL_API_ROOT;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
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

export async function lookupDomainReputation(domain: string, apiKey: string | undefined, request: FetchLike = fetch): Promise<ReputationResult> {
  const key = getApiKey(apiKey);
  if (!key) return { status: "not-configured", message: "VirusTotal reputation lookup was not run because VIRUSTOTAL_API_KEY is not configured. OKAY" };

  let response: Response;
  try {
    response = await request(`${VIRUSTOTAL_API_ROOT}/domains/${encodeURIComponent(domain)}`, { headers: headers(key) });
  } catch {
    return { status: "network-error", message: "Could not reach VirusTotal. Check the network connection and try again." };
  }
  if (!response.ok) return resultForStatus(response.status);

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return { status: "malformed-response", message: "VirusTotal returned invalid JSON." };
  }
  if (!isRecord(payload) || !isRecord(payload.data) || !isRecord(payload.data.attributes)) {
    return { status: "malformed-response", message: "VirusTotal returned an unexpected domain report." };
  }

  const attributes = payload.data.attributes;
  const rawStats = attributes.last_analysis_stats;
  if (rawStats !== undefined && !isRecord(rawStats)) return { status: "malformed-response", message: "VirusTotal returned inv alid analysis statistics." };
  const stats: AnalysisStats | undefined = rawStats ? {
    malicious: readStat(rawStats.malicious), suspicious: readStat(rawStats.suspicious),
    harmless: readStat(rawStats.harmless), undetected: readStat(rawStats.undetected),
  } : undefined;
  const lastAnalysisAt = typeof attributes.last_analysis_date === "number" ? new Date(attributes.last_analysis_date * 1_000).toISOString() : undefined;

  return { status: "success", domain, stats, lastAnalysisAt, reportUrl: `https://www.virustotal.com/gui/domain/${encodeURIComponent(domain)}`, message: "VirusTotal domain report retrieved." };
}

export async function checkVirusTotalKey(apiKey: string | undefined, request: FetchLike = fetch): Promise<ReputationResult | boolean > { // check returning type, shall we create new? 
  const key = getApiKey(apiKey);
  if (!key) return { status: "not-configured", message: "VIRUSTOTAL_API_KEY is not configured." };
  return true
  /*
  DO WE NEED THIS? TODO
  let response: Response;
  try {
    response = await request(`${VIRUSTOTAL_API_ROOT}/metadata`, { headers: headers(key) });
  } catch {
    return { status: "network-error", message: "Could not reach VirusTotal. Check the network connection and try again." };
  }
  if (response.ok) return { status: "success", message: "VirusTotal API key is accepted." };
  const error = resultForStatus(response.status);
  return { status: error.status === "no-report" ? "api-error" : error.status, message: error.message };
  */ 
}
