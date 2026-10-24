# Privacy

Sentinella does not implement its own telemetry or cloud sample submission. Its ClamAV adapter scans locally. FreshClam contacts the official mirrors when updating signatures. Microsoft Defender follows the cloud and sample-submission settings already configured in Windows; Sentinella does not silently change them.

Activity history, encrypted quarantine and local backups stay on the computer. Exported reports can include local paths, registered protection products, startup entries and network-inventory metadata. Such reports, quarantine contents and personal machine logs are not part of this repository and must not be posted publicly without review.

GitHub Actions runs the build on a hosted Windows runner. The workflow publishes only the unsigned build artifact and does not access the maintainer's personal PC or upload its diagnostics.

Project maintenance is handled through the public repository owned by [gabryrinaldi4-a11y](https://github.com/gabryrinaldi4-a11y). Avoid sharing private information in public issues. No external signing application has yet been submitted.
