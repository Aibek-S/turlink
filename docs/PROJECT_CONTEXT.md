# Turlink Project Context

## Purpose

Turlink is a school informatics project about filtering and checking links for visible indicators that deserve caution. Its initial audience is students. The goal is to build a small, understandable tool and document its design and limitations honestly.

This repository is the code project. The earlier school-project documentation discussed an MVP, requirements, SDLC, comparison of existing solutions, and plans for surveys/interviews. Real student survey responses and interview records were not available; do not invent research data or present planned research as completed.

## Current implementation

The initial MVP lives in `apps/service` and is a command-line TypeScript program. It parses one URL and checks a short list of visible signals:

- Non-HTTPS HTTP links.
- IPv4 addresses used as the host.
- Internationalized domain labels beginning with `xn--`.
- Credentials embedded before the hostname.

The CLI does not fetch or open a submitted URL, contact reputation services, inspect page content, or determine that a link is safe. No warnings means only that these few local checks found no listed signal. A warning is not proof of malicious intent.

Examples:

```sh
pnpm install
pnpm dev -- https://example.com
pnpm dev -- http://127.0.0.1/login
pnpm dev -- https://user@example.com
pnpm check
```

The service uses Node's built-in TypeScript type stripping for development (`node --experimental-strip-types`). The root package is an npm-style workspace managed with pnpm. TypeScript and Node types are service dev dependencies. Keep tooling compatible with the Node version in use and avoid adding unnecessary build-script dependencies.

## Architecture direction

The repository is prepared for a gradual expansion, not an implementation of those future apps yet:

- `apps/service`: current CLI; the likely place for reusable link-analysis domain logic.
- `apps/web`: reserved for a future React frontend.
- `apps/extension`: reserved for a future browser extension.

If multiple clients are added, extract shared URL analysis into a focused package (for example `packages/core`) rather than coupling business logic to an Express server or browser APIs. Add Express only when a real HTTP service contract is needed. Keep interfaces suitable for reuse by CLI, web, and extension clients.

## Engineering constraints

- Be conservative with conclusions and user-facing security language.
- Never claim a URL is safe from absence of a warning.
- Do not silently upload URLs, browse to them, or call third-party services. Any such behavior needs an explicit product decision, privacy documentation, and tests.
- Validate schemes and inputs explicitly. Treat parsing and normalization carefully, especially credentials, Unicode/punycode, redirects, and private/local addresses if network requests are ever introduced.
- Add tests as the rules expand; the initial MVP currently has a typecheck but no dedicated automated test suite.
- Keep dependencies and architecture minimal until requirements justify expansion.

## GitHub workflow

Treat GitHub as the source of truth for work tracking and review:

1. Issue describes the task, rationale, and acceptance criteria.
2. A focused branch is created from `main`.
3. Changes are pushed to that branch and proposed in a pull request linked to the issue.
4. At least one other person reviews and approves the PR; required checks pass.
5. The PR is merged into `main` only after those conditions are met.

Direct pushes to `main` and force pushes to shared branches are not allowed. Follow `CONTRIBUTING.md`. Server-side branch protection must enforce at least one approval and disallow direct updates to `main`; do not assume that writing this policy down configures GitHub automatically.

The repository's very first bootstrap commit was placed on `main` while initializing this empty repository, before a pull request could exist. This is a one-time repository setup exception, not a model for future changes. All subsequent commits must follow the issue and pull request workflow above.

## Handoff guidance

Before implementing a feature, inspect the current code and issues instead of assuming this handoff is exhaustive. Preserve the privacy and safety constraints above, keep the first implementation small, and update this document when architecture or product behavior materially changes.
