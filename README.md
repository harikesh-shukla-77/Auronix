# Auronix

Personal AI assistant with security foundation and voice interface.

## Structure

- `src/auronix/` — Security subsystem (TPM attestation, trust broker, R9)
- `src/auronix_product/` — Voice assistant (Whisper STT, Ollama LLM, Mac actions)
- `audit/` — Security audit reports (R9 phases C3-A through C3-C-R1)
- `docs/` — Architecture, commands, roadmap
- `tests/` — Test suites for both subsystems
- `scripts/` — Setup and dev scripts

## Install


## Run voice assistant

    ./scripts/dev.sh          # voice mode
    ./scripts/dev.sh --text   # text mode (no mic)

## Status

- R9 security: source-level closed (ACCEPTED WITH FINDINGS)
- Voice assistant: v2 working (6/6 tests)
- Physical TPM: pending hardware
- KMS/HSM: pending provisioning

## Audit trail

115+ security audit reports in audit/ — R9 phases C3-A through
C3-C-R1. Frozen source hashes preserved for independent verification.

## Structure

- src/auronix/ — R9 security subsystem
- src/auronix_product/ — Voice assistant
- audit/ — Security audit reports
- docs/ — Architecture, commands, roadmap
- tests/ — Test suites
- scripts/ — Setup and dev scripts

