# Android Compatibility Model

Author: h3st4k3r

DroidCustos is designed for Android 8 and later. Support is capability-based rather than based only on device names.

## Target SDK range

```text
Android 8     SDK 26
Android 9     SDK 28
Android 10    SDK 29
Android 11    SDK 30
Android 12    SDK 31 and 32
Android 13    SDK 33
Android 14    SDK 34
Android 15    SDK 35
Android 16    SDK 36
```

## OEM plugin families

```text
AOSP
Google Pixel
Samsung One UI
ASUS and ROG UI
Xiaomi MIUI and HyperOS
OnePlus OxygenOS
OPPO ColorOS
Realme UI
Motorola
Vivo and iQOO
Huawei EMUI and Harmony-derived Android builds
```

An OEM family entry means that DroidCustos contains detection and collector definitions. It does not mean every model and firmware has been physically validated.

## Validation levels

```text
DECLARATIVE
The plugin exists and passes schema tests.

EMULATOR
The core collector has been exercised on an emulator for the SDK.

PHYSICAL
A physical device completed the standard acquisition.

DEEP
A physical device completed optional deep acquisition.

REGRESSION
The device and firmware family are covered by repeatable regression tests.
```

## Required validation record

Each physical test should record:

- Manufacturer and model.
- Android version and SDK.
- Build fingerprint.
- Security patch.
- ROM family.
- User and profile configuration.
- Root state.
- AndroidQF version.
- MVT version.
- Successful, unsupported, denied and failed collectors.
- Coverage score.
- Test case SHA-256.
