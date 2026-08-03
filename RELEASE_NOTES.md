# DroidCustos 0.3.2 Release Notes

Release date: 2026-08-03  
Author: h3st4k3r  
Status: Public alpha

## Purpose

This release prepares DroidCustos for public distribution with complete operator documentation, explicit audience and scope guidance, third-party licensing notices and clean reproducible source packages.

## Added

- Complete public README and end-to-end workflow.
- Dedicated installation guide for macOS and Linux.
- Complete operator user guide.
- Report interpretation guide.
- Legal and ethical use policy.
- Troubleshooting guide.
- Third-party tool and license inventory.
- Security policy.
- Contribution policy.
- Machine-readable citation metadata.
- Public-release packaging checks that exclude caches, build artifacts and case data.

## Clarified

- DroidCustos is a logical acquisition and triage orchestrator, not a physical imaging tool.
- The project is public alpha and has not received independent laboratory validation.
- MVT and AndroidQF require explicit data-owner consent under the MVT License 1.1.
- Law-enforcement use of the integrated workflow is limited to consent-based examinations that also satisfy applicable law and procedure.
- A negative IOC result applies only to successfully acquired artifacts.

## Functional foundation

This release includes the 0.3.1 verdict and reporting corrections:

- MVT heuristics are separated from confirmed IOC matches.
- Empty `matched_indicator` values cannot generate a confirmed-IOC verdict.
- `0 CRITICAL alerts` is not parsed as a critical alert.
- Reports include searchable HTML and complete CSV tables.
- Package parsing preserves identifiers when APK paths contain Base64 padding.
