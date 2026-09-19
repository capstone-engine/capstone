# AGENTS.md

Guidance for coding agents working on Capstone.

## Project documentation

Follow [CONTRIBUTING.md](CONTRIBUTING.md), including its AI guidelines.
Do not write commit messages or PR descriptions. Translating text written
by the contributor is allowed.

Read the documentation relevant to the task:

- [BUILDING.md](BUILDING.md): build options and platform instructions.
- [tests/README.md](tests/README.md): test tools and YAML conventions.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): decoding and detail mapping.
- [Auto-Sync](suite/auto-sync/README.md) and its
  [update rules](suite/auto-sync/ARCHITECTURE.md): generated and translated code.

## Changes

- Check the working tree before editing and preserve existing work.
- Establish the expected behavior and keep the fix focused on the task.
- Follow nearby code and reuse existing helpers. Avoid unrelated refactoring,
  formatting, and dependencies.
- Use the repository's `.clang-format` for C and Black for Python.
- Update documentation when the change affects an API or documented behavior.
- Before editing generated code, check how the module is updated. Follow its
  workflow so the fix survives regeneration.

## Tests

- Reproduce the bug before fixing it. Record the bytes, architecture, mode,
  syntax, and options needed to reproduce an instruction bug.
- Extend an existing test where possible. Add cases for distinct affected
  behavior and avoid duplicate coverage.
- Check the fields involved in the bug. Correct assembly text alone does not
  verify operand access, register access, or instruction groups.
- Confirm the regression test fails before the fix and passes afterward.
  Run the relevant tests against the local build.

## Before finishing

Review the diff and run `git diff --check`. Keep build output and investigation
notes out of the patch. Briefly report what changed and which tests actually
ran, including any failed, skipped, or blocked checks.
