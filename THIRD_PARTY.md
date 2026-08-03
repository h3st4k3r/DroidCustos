# Third-Party Tools, Data and Licenses

Author: h3st4k3r  
Applies to: DroidCustos 0.3.2

DroidCustos orchestrates external projects but does not claim ownership of them. Source releases do not bundle their binaries or source trees.

## MVT

- Project: Mobile Verification Toolkit
- Upstream: https://github.com/mvt-project/mvt
- Role: AndroidQF and bug-report analysis; native IOC support
- License: MVT License 1.1
- Important condition: explicit data-owner consent is required by the upstream license

## AndroidQF

- Project: Android Quick Forensics
- Upstream: https://github.com/mvt-project/androidqf
- Role: portable Android logical acquisition
- License: MVT License 1.1
- Important condition: explicit data-owner consent is required by the upstream license

## MVT Indicators

- Upstream: https://github.com/mvt-project/mvt-indicators
- Role: index of public mobile threat-intelligence sources
- Terms: individual indicator feeds can have their own attribution or use conditions

## ALEAPP

- Project: Android Logs Events And Protobuf Parser
- Upstream: https://github.com/abrignoni/ALEAPP
- Role: optional parsing of Android extraction artifacts
- License: MIT

## Android Platform Tools

- Provider: Google Android Developers
- Upstream documentation: https://developer.android.com/tools/adb
- Role: ADB communication and bug-report collection
- Distribution terms: governed by the Android SDK and platform-tools terms

## Android SDK Build Tools

- Tools: `apksigner`, `aapt2`
- Role: optional APK signing and metadata enrichment
- Distribution terms: governed by Android SDK terms

## STIX2 sources

DroidCustos can download multiple public or operator-configured STIX2 bundles. The tool records provider, source URL, retrieval metadata and hash. Operators must review each source's terms, quality, scope, revocation status and retention requirements.

## Python dependencies

Direct runtime dependencies are declared in `pyproject.toml`. Transitive dependencies are resolved by pip and remain governed by their own licenses. Generate an environment-specific dependency inventory before controlled deployment.

## Supply-chain note

`doctor --fix`, `doctor --with-aleapp` and `update-iocs` use the network and retrieve current upstream content. Restricted environments should stage, review, hash and approve these materials before deployment, then use cached tools and `--no-update` during examinations.
