# DroidCustos OEM Plugin SDK

Author: h3st4k3r

OEM collectors are stored as YAML under `droidcustos/plugin_data`.

## Example

```yaml
id: example-oem
manufacturers:
  - example

defaults:
  sdk_min: 29
  privilege: shell
  timeout: 180
  sensitivity: system

collectors:
  - id: security-state
    description: Example OEM security properties
    required_commands:
      - sh
    command:
      - "{adb}"
      - -s
      - "{serial}"
      - shell
      - sh
      - -c
      - "getprop | grep -Ei 'security|verifiedboot' || true"
    output: security-state.txt
```

## Fields

`id` identifies the plugin or collector.

`manufacturers` accepts normalized ROM families, manufacturer names or `*`.

`sdk_min` and `sdk_max` limit execution by Android SDK.

`privilege` accepts `shell` or `root`.

`required_commands` lists Android shell commands that must be available.

`required_dumpsys` lists services that must appear in `dumpsys -l`.

`timeout` is expressed in seconds.

`sensitivity` documents whether output is system, network, personal or private data.

`command` is a fixed argument array. Supported placeholders are `{adb}`, `{serial}` and `{user}`.

`output` is relative to `01_evidence/plugins/<plugin-id>` and can contain `{user}`.

## Security requirements

- Plugin definitions must remain local reviewed project content.
- Do not execute commands downloaded from intelligence feeds.
- Do not use shell interpolation for untrusted device values.
- Collectors must be read-only whenever Android permits.
- A root collector must declare `privilege: root`.
- Privacy-sensitive output must declare an appropriate sensitivity.
- Unsupported collectors must be recorded instead of silently ignored.
