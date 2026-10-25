# Privacy

Sentinella does not implement its own telemetry or cloud sample submission. Its ClamAV adapter scans locally. FreshClam contacts the official mirrors when updating signatures. Microsoft Defender follows the cloud and sample-submission settings already configured in Windows; Sentinella does not silently change them.

Activity history, encrypted quarantine and local backups stay on the computer. Exported reports can include local paths, registered protection products, startup entries and network-inventory metadata. Such reports, quarantine contents and personal machine logs are not part of this repository and must not be posted publicly without review.

GitHub Actions runs the build on a hosted Windows runner. The workflow publishes only the unsigned build artifact and does not access the maintainer's personal PC or upload its diagnostics.

Project maintenance is handled through the public repository owned by [gabryrinaldi4-a11y](https://github.com/gabryrinaldi4-a11y). Avoid sharing private information in public issues. No external signing application has yet been submitted.

Application-control drafts and exported XML include the selected Windows SID, local paths and file hashes. The administrative backup stays under ProgramData with administrator/SYSTEM write permissions. These data are not uploaded automatically and must not be committed to the public repository.

The optional background agent stores selected folder paths and local alerts in the user profile. Process command arguments are evaluated in memory and are not persisted. Activation, login startup and signature-network updates require explicit user choices. No telemetry endpoint is implemented.

The separately installed browser extension stores rules in storage.local, has no content scripts and sends no browsing history or file samples. Its optional CERT Polska list download contacts hole.cert.pl, which can observe the request IP. No list is fetched until that source is configured. Automatic program updates are disabled in this build.
