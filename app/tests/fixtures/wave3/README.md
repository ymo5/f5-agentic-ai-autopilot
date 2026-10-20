# Wave 3 fixtures — provenance

| File | Origin | Real or synthetic |
|---|---|---|
| `bigip_c_real_capture_min.json` | **REAL** BIG-IP_C (21.1.0.3) read-only capture, Phase 1, 2026-10-14 (`collected_at` 1792032849.457): owner ran `scripts/observe-collect.sh --no-upload`, then `scripts/observe-share.py` (v1); minimized offline with `observe-share.py` v2 (memory-host entries only; CPU idle fields only). Response structures, status codes and values are unmodified otherwise. Contains no credentials (collector + share redaction; secret scan 0 hits). Excludes virtual servers, pools, monitors, iRules, SSL profiles, host name. The full capture stays private on the owner's workstation | **real** |
| `lab_stored_observe.json` | **REAL** stored Observe model (assessment "NEw Test", 2026-10-13), copied from the workstation backup | **real** (normalized model, pre-Wave-3 format) |
| `two_bigip.json` | hand-written two-device inventory in documentation address space | **synthetic** |

Tests that use real evidence pass an explicit evaluation time (`now`) so freshness results are deterministic.
