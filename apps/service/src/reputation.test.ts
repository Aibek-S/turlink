import assert from "node:assert/strict";
import test from "node:test";
import { checkVirusTotalKey, lookupDomainReputation, type FetchLike } from "./reputation.ts";

function response(body: unknown, status = 200): Response {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

test("does not make a request when no API key is configured", async () => {
  let requested = false;
  const request: FetchLike = async () => {
    requested = true;
    throw new Error("should not be called");
  };

  const result = await lookupDomainReputation("example.com", undefined, request);
  assert.equal(result.status, "not-configured");
  assert.equal(requested, false);
});

test("queries only the hostname through the VirusTotal domain endpoint", async () => {
  let requestUrl = "";
  let requestHeaders: HeadersInit | undefined;
  const request: FetchLike = async (url, init) => {
    requestUrl = String(url);
    requestHeaders = init?.headers;
    return response({ data: { attributes: { last_analysis_stats: { malicious: 1, suspicious: 2, harmless: 3, undetected: 4 }, last_analysis_date: 1_700_000_000 } } });
  };

  const result = await lookupDomainReputation("example.com", "secret-key", request);
  assert.equal(requestUrl, "https://www.virustotal.com/api/v3/domains/example.com");
  assert.deepEqual(requestHeaders, { accept: "application/json", "x-apikey": "secret-key" });
  assert.equal(result.status, "success");
  assert.equal(result.stats?.malicious, 1);
  assert.equal(result.lastAnalysisAt, "2023-11-14T22:13:20.000Z");
});

for (const [status, expected] of [[401, "authentication-failed"], [403, "authentication-failed"], [404, "no-report"], [429, "rate-limited"]] as const) {
  test(`handles HTTP ${status}`, async () => {
    const request: FetchLike = async () => response({}, status);
    const result = await lookupDomainReputation("example.com", "key", request);
    assert.equal(result.status, expected);
  });
}

test("handles other HTTP errors without exposing the key", async () => {
  const request: FetchLike = async () => response({}, 500);
  const result = await lookupDomainReputation("example.com", "never-print-this", request);
  assert.equal(result.status, "api-error");
  assert.equal(result.message.includes("never-print-this"), false);
});

test("handles network and malformed-response failures", async () => {
  const network: FetchLike = async () => { throw new Error("offline"); };
  assert.equal((await lookupDomainReputation("example.com", "key", network)).status, "network-error");

  const invalidJson: FetchLike = async () => response("not json");
  assert.equal((await lookupDomainReputation("example.com", "key", invalidJson)).status, "malformed-response");
});

test("checks a configured key without submitting a domain", async () => {
  let requestUrl = "";
  const request: FetchLike = async (url) => {
    requestUrl = String(url);
    return response({ data: {} });
  };
  const result = await checkVirusTotalKey("key", request);
  assert.equal(result.status, "success");
  assert.equal(requestUrl, "https://www.virustotal.com/api/v3/metadata");
});
