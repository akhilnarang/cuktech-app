# Agent notes

Layout and user docs: [README.md](README.md). Protocol and firmware facts: [docs/README.md](docs/README.md).

## Safety

The user runs anything that touches a real account, a real charger or a phone:
Xiaomi login, cloud bind/unbind, BLE writes, firmware install, APK install. Prepare the
command, then give it to the user.

Commit only interoperability facts and our own code. Vendor code, decompiled output, APKs,
plugins, firmware, tokens, keystores and account data stay out of the repo (`/artifacts/`
and `.private/` are ignored for local copies).

## Checks

Run all of these before you commit. Each one must pass with zero skips.

```bash
cd scripts && uv run -m unittest discover -s tests -t . && uv run -m unittest discover -s tests_firmware -t .
cd app && ./gradlew :app:testDebugUnitTest :app:lintDebug :app:assembleDebug :app:compileDebugAndroidTestKotlin
```

`scripts/tests/__init__.py` blocks network, BLE and the real `HOME`; the suite exits
non-zero on any blocked attempt, even one the code under test catches. Each run uses its own
`scripts/.test-scratch/<pid>-*` directory, so parallel runs are safe.

## Tests

Each test protects an observable contract and goes red on a credible regression. Take
expected values from an **independent** source:

- Crypto: published vectors (RFC 6229, RFC 5869, RFC 5903, FIPS).
- Protocol: frames captured from a real charger, or bytes derived by hand from
  `docs/firmware/`.
- Fakes: `scripts/tests/fakepeer.py` has its own crypto, so a bug shared by both sides of
  `cuktech_pc.crypto` still fails. Keep it free of `cuktech_pc` imports.

Assert on behaviour at the public boundary. Match a message by its full contents; a
one-byte match against random data caused a 2% flake in `test_07_v2bind`. Put a seam in
production code only when production uses it too; delete helpers that only tests call.

A bug fix ships with one regression test, at the owner, that fails on the old code.

## Code and docs

- Python 3.14 (`scripts/.python-version`), deps pinned in `pyproject.toml` + `uv.lock`;
  run everything with `uv run`. Annotations need no `from __future__` import.
- Public functions get docstrings with `Args:` and `Returns:`.
- Human-facing text (README, docs, UI strings, CHANGELOG) uses ASD-STE100 style: short
  sentences, active voice, one instruction per sentence.
- A firmware claim names the firmware version and the address or capture that shows it.
  Mark guesses as unresolved.
- Add user-visible changes to `CHANGELOG.md` under `## Unreleased`.
- The app ID is `dev.akhilnarang.cuktech`. A new app ID or signing key stops updates
  installing over the old app and loses the saved token; call that out in the CHANGELOG.
