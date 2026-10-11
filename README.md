# Turlink

Turlink is a school project exploring how to identify and filter potentially unsafe links.

## Project structure

- `apps/service` - TypeScript command-line link checker (current MVP).
- `apps/web` - reserved for a future web application.
- `apps/extension` - reserved for a future browser extension.

See [`docs/PROJECT_CONTEXT.md`](docs/PROJECT_CONTEXT.md) for the project brief and technical handoff. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the required GitHub workflow.

## Requirements

- Node.js 22.6 or newer (the CLI uses Node's built-in TypeScript type stripping).
- pnpm 10 or newer.

## Getting started

```sh
pnpm install
pnpm dev -- https://example.com
```

The current MVP performs conservative, local checks. It does not submit URLs to external services and does not claim that a link is safe based on reputation data.

## Contributing

Use an issue and a feature branch, then open a pull request. Do not push directly to `main`; every change must receive at least one approval before merge. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Checks

```sh
pnpm check
```
