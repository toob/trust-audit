# Contributing

The bar is the README's promise: **read-only, offline, and never a false “clean”.** A change that
weakens one of them will not be merged, however convenient.

- Plain POSIX `sh`; no bashisms in `trust-audit`. It must pass `shellcheck` with no disabled rule
  (`shellcheck trust-audit update-list tests/*.sh`).
- Every behaviour change comes with a test in `tests/test-trust-audit.sh` using throw-away
  certificates. Include the *failure* case: what must not be reported clean.
- New store location: say which system/package uses it and link its documentation in the pull
  request. A path you could not verify goes in the README's “not tested” list.
- List changes: run `./update-list`, review the diff, and explain any removal. Curated incidents
  go in `sources/curated.tsv`, each entry with a
  fingerprint from a published source, a factual one-line reason, and references you have opened
  and checked (one or more URLs, space-separated). Never add a fingerprint from memory.
- Keep it small. A new dependency, or a feature that needs one, needs a strong argument.

Run before opening a pull request:

```sh
tests/test-trust-audit.sh && shellcheck trust-audit update-list tests/*.sh
```
