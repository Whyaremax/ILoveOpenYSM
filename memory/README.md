# ILoveOpenYSM Research Notes

This folder is a small public note bundle copied down from the wider local YSM
research tree.

It is intentionally curated:

- enough detail to show how the native/runtime side was studied
- enough detail to explain why the extractor behaves the way it does
- not a raw dump of every trace, scratch note, or private runtime artifact

## Notes

- [native_library_runtime_evidence_may5.md](native_library_runtime_evidence_may5.md)
  - short overview of why we believe `libysm-core` is a real working runtime
- [native_antidebug_and_bootstrap_may5.md](native_antidebug_and_bootstrap_may5.md)
  - how the launcher/debugger/startup gate was found and how far the JNI path was confirmed
- [native_import_and_loader_path_may5.md](native_import_and_loader_path_may5.md)
  - how the native side ingests `custom/*.ysm` and `cache/server/*`
- [native_export_and_truth_capture_may5.md](native_export_and_truth_capture_may5.md)
  - what we know about native export roots, command shape, and official-export comparison
- [runtime_boundary_and_platform_limits_may5.md](runtime_boundary_and_platform_limits_may5.md)
  - Java transport vs native payload handling, plus current platform limits
- [extractor_recovery_and_limits_may5.md](extractor_recovery_and_limits_may5.md)
  - what the offline extractor recovers today and where the important gaps still are

## Scope note

ILoveOpenYSM remains the public offline extractor/decoder repo.
These notes exist to document the evidence behind the work, not to turn the repo
into a full runtime-debug bundle.
