# Sentinella Free

Experimental Windows security software: WPF interface, ClamAV scans, encrypted manual quarantine, local versioned backups, AppLocker management, per-user background monitoring and an optional browser domain filter. Original code: MIT.

**Development version 0.4, not a complete or independently validated replacement for an established antivirus.** Keep the current antivirus and Smart App Control enabled. No equivalence or superiority claim is made.

## Modules

- Explicit file/folder/archive scans with a separately distributed ClamAV engine and official databases. FreshClam authentication stays enabled.
- Verified manual quarantine using AES-GCM and DPAPI; restore never overwrites existing files.
- Personal SHA256 rules, local versioned backups and Windows protection inventory. Local backups are not immutable ransomware recovery.
- Per-user AppLocker authoring, offline evaluation, explicitly confirmed audit/enforcement and guarded restore: [APP_CONTROL.md](APP_CONTROL.md).
- A per-user background agent with bounded/debounced file monitoring, incomplete/error states, optional login startup and official signature updates. Scans happen after writes, not before execution.
- Non-destructive process-pattern and file-burst warnings. These are uncertain signals, not malware verdicts; command arguments are not persisted.
- An optional Manifest V3 extension: native domain blocking, personal exceptions and opt-in CERT Polska refresh. It starts disabled and is not installed by the desktop app.
- Local component-hash checks and an RSA-PSS release-manifest verifier. Automatic program installation is disabled until a pinned release key and complete release process exist.

Scope, operation, permissions and limitations: [CONTINUOUS_PROTECTION.md](CONTINUOUS_PROTECTION.md).

## Build and checks

Windows x64, PowerShell and .NET SDK 10:

```powershell
./build.ps1
```

The workflow builds an unsigned review artifact, runs harmless core and native AppLocker evaluation tests, and tests domain blocking and exceptions in an isolated Chromium profile. These checks do not install endpoint policies, startup entries or extensions in personal browsers. A green build is not an antivirus efficacy certification.

ClamAV binaries/databases are upstream components, not committed here. The app expects runtime/clamav and runtime/database beside the executable, or explicit --runtime-root and --state-root paths.

## Runtime and signing

Windows blocked components of the earlier 0.2 build. Unsigned 0.3 subsequently started normally on the development PC with Smart App Control On. This does not guarantee startup of every later build or validate all features. No security policy was weakened. No signing provider has accepted this project.

[Code signing policy](CODE_SIGNING.md) · [Privacy](PRIVACY.md) · [Security](SECURITY.md)

No proprietary Bitdefender or Malwarebytes binaries, drivers, signatures or reverse-engineering evidence are included. Maintainer: [gabryrinaldi4-a11y](https://github.com/gabryrinaldi4-a11y). Original source: [MIT](LICENSE.txt); .NET and ClamAV retain their own licenses.
