# Code signing policy

Current status: unsigned development builds. No provider has accepted this project, and no SignPath subscription or certificate is active. A code signature is not a certification of antivirus efficacy.

The initial repository owner and maintainer is [gabryrinaldi4-a11y](https://github.com/gabryrinaldi4-a11y). The maintainer reviews changes and approves releases. MFA must be enabled for repository and signing-service access before a signing application is submitted; this document does not claim that account configuration has been verified.

Only original components built from this repository may be submitted for signing:

- SentinellaFree.exe
- SentinellaFree.dll
- Sentinella.Core.dll

Microsoft .NET and ClamAV retain their own licenses, ownership and signing status. Their binaries must not be signed as original Sentinella components.

Each future signing request must be approved by the maintainer and tied to a reviewed commit and its CI artifact. No private keys or signing credentials belong in this repository. The current CI compiles, runs read-only application-control checks and uploads an unsigned review artifact; it does not request signatures or publish releases automatically.

A possible free signing application will be evaluated against [SignPath Foundation requirements](https://signpath.org/terms.html). Acceptance is not guaranteed, particularly for a new project. If accepted, this policy must be updated with the actual provider attribution and approval configuration before a signed release is announced.
