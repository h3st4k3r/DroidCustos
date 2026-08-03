# Android Forensic Playbook

Author: h3st4k3r

## Preparation

1. Obtain explicit authorization.
2. Record device condition, time, battery, SIM state and visible notifications.
3. Avoid rebooting, updating, uninstalling or resetting the device.
4. Prepare encrypted host storage with sufficient free capacity.
5. Enable and authorize ADB only when required.

## Capability inspection

```bash
.venv/bin/droidcustos inspect --users all
```

Review visible users, profiles, storage roots, root state and collector coverage before acquisition.

## Standard acquisition

```bash
.venv/bin/droidcustos scan \
  --users all \
  --operator h3st4k3r \
  --case-id CASE-001
```

## Deep acquisition

```bash
.venv/bin/droidcustos scan \
  --deep \
  --users all \
  --operator h3st4k3r \
  --case-id CASE-001
```

Use `--copy-user-files` only when the case scope requires original shared files.

Use `--root-mode auto` only when root access already existed and its use is explicitly authorized.

## Immediate response to an IOC match

1. Do not reset or uninstall applications.
2. Preserve the complete case directory.
3. Verify the evidence manifest.
4. Create a signed case seal.
5. Export an encrypted copy to separate controlled storage.
6. Review the unified timeline around matched events.
7. Preserve matched APKs, certificates, domains, IP addresses and process names.
8. Escalate to a qualified mobile-forensics laboratory when exploitation or mercenary spyware is suspected.

## Closure

1. Verify the final evidence manifest.
2. Sign the case seal.
3. Export an encrypted archival copy.
4. Record the final custodian and storage location outside the tool.
5. Disable USB debugging and revoke host authorizations when operationally appropriate.
