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
- For architecture code, use updated modules such as ARM, PPC, Mips,
  SystemZ, and Xtensa as style references. Reuse existing helpers where
  appropriate.
- Avoid unrelated refactoring, formatting changes, or dependency changes.
- Prefer editing existing files when the change fits their purpose.
  Add files only when required by the task or project conventions.
- Keep comments focused on non-obvious behavior and constraints.
  Do not restate the code or narrate the editing process.
- Use the repository's `.clang-format` for C and Black for Python.
- Documentation must be written by a human. AI-generated documentation is forbidden. 
- API changes must be documented in `docs/cs_v6_release_guide.md`. This must be done by the developer.
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

- Review your diff for unnecessary comments, files, and abstractions.
  Remove additions that do not help implement, explain, or test the change.
- Run `git diff --check`. Keep build output and investigation notes out of
  the patch. Briefly report what changed and which tests actually ran,
  including any failed, skipped, or blocked checks.
