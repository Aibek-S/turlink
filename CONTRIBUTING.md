# Contributing

All project changes must follow the GitHub issue and pull request workflow.

1. Create or identify a GitHub issue describing the change and its acceptance criteria.
2. Create a branch from `main`, using a short prefix such as `feat/`, `fix/`, or `docs/` and a reference to the issue when practical.
3. Make a focused change, run the checks listed in the issue or project documentation, and commit it on that branch.
4. Push the branch and open a pull request against `main`. Link the issue with `Closes #<number>` when the PR completes it.
5. Request review. At least one person other than the PR author must approve the changes. Address review feedback and wait for required checks.
6. Merge the pull request only after approval and passing checks. Delete the branch after merge when appropriate.

## Protected branch expectations

- Never push directly to `main` or force-push a shared branch.
- `main` should require pull requests and at least one approving review.
- Require approval of the most recent reviewable push and require conversation resolution when those options are available.
- Do not bypass these rules, including as an administrator, except for a documented emergency approved by the repository owner.
- Keep GitHub branch protection configured to enforce this policy. Documentation is not a substitute for server-side protection.

## Before opening a pull request

- Run `pnpm check`.
- Run relevant CLI examples from `docs/PROJECT_CONTEXT.md`.
- Summarize the behavior change, validation, limitations, and linked issue in the PR description.
