# Turlink

Turlink is a school project exploring how to identify and filter potentially unsafe links.

## Project structure

- `apps/service` - TypeScript command-line link checker (current MVP).
- `apps/web` - reserved for a future web application.
- `apps/extension` - reserved for a future browser extension.

See [`docs/PROJECT_CONTEXT.md`](docs/PROJECT_CONTEXT.md) for the project brief and technical handoff. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the required GitHub workflow.

## Requirements

- Node.js 22.9 or newer (the CLI uses built-in TypeScript type stripping and optional `.env` loading).
- pnpm 10 or newer.

## Getting started

```sh
pnpm install
pnpm dev -- https://example.com
```

The default command performs conservative, local checks. It does not make network requests and does not claim that a link is safe.

### Optional VirusTotal domain reputation

Reputation lookup is opt-in. It sends only the normalized hostname, never the complete URL, path, query, or credentials:

```sh
cp .env.example .env
# Set VIRUSTOTAL_API_KEY in .env. Do not commit this file.
pnpm dev -- --reputation https://example.com/path?private=value
```

Before each lookup, Turlink prints a privacy notice. VirusTotal states that indicators queried via its API can be scanned and added to its dataset, where they may be accessible to the community. Do not use reputation lookup for sensitive, confidential, or personally identifiable domains.

Without `VIRUSTOTAL_API_KEY`, local checks still work and `--reputation` makes no network request. A report with zero malicious or suspicious detections is not proof that a domain is safe.

To validate a configured key without submitting a domain, run:

```sh
pnpm dev -- --reputation-health
```

This contacts VirusTotal's authenticated metadata endpoint and consumes one API request. VirusTotal's public API currently documents plan limits including 4 requests per minute and 500 per day; limits depend on the plan and can change. Turlink does not retry reputation requests automatically.

## Contributing

Use an issue and a feature branch, then open a pull request. Do not push directly to `main`; every change must receive at least one approval before merge. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Checks

```sh
pnpm check
pnpm test
```
