# Official AD1204 charger plugin: acquisition and first findings

> **Provenance and scope.** This is interoperability research on publicly
> distributed software. Its purpose is to let independent software talk to a
> charger that the reader owns. It records only the facts necessary for that
> purpose: request formats, identifiers, offsets, hashes and observed behavior.
> This repository does not redistribute vendor source code, decompiled code,
> APKs, plugin packages, firmware or other vendor binaries.

Later work: [app 0.6.6](app-protocol-labels-0066.md) uses the vendor names. It
keeps C1/C2 09 as a tentative miPPS alias and shows the USB-A 02 conflict.
[Debug/upgrade tracing](plugin-debug-and-upgrade-followup.md) maps the account
gate, the empty logging callbacks and the native BLE OTA auth dispatch. The
statements below about unchanged app labels apply to the first acquisition
stage.

## Acquired artifact

On 2026-10-15, a read-only `/v2/plugin/fetch_plugin` call was successful with
`code=0`. It used the recovered native Mi Home request and the authorized CN
session. There was no new login, account binding, firmware update or charger
command. The failed SDK-shaped lookup in stage 19 is a separate observation.
This success does not show which difference in the request was important.

The response identifies:

| Field | Value |
| --- | --- |
| Model | `njcuk.fitting.ad1204` |
| Plugin ID | `1028581` |
| Plugin version | `60` |
| Plugin package ID | `1896060` |
| Response `sdk_version` | `10116` |
| ZIP bytes | `4664265` |
| ZIP SHA-256 | `9f1198fb6a096715ae03e3f92afca7cde4fde1b68adfa5ba6f4ed5df61692fe2` |
| ZIP MD5 | `5b9cc788c00df5e00efdfdf60f425e8f` |
| Uncompressed member bytes | `5433726` |

**Correction to earlier shorthand:** `1896060` is the plugin **package ID**. It
is not the plugin version. The version field is `60`.

Xiaomi returned the plugin from its own CDN as
`signed_10110_1028581_60_ANDROID_bundle_5b9cc788c00df5e00efdfdf60f425e8f.zip`.
This repository does not link to or include the plugin.
The MD5 in the filename is the same as the measured ZIP MD5. This agreement of
names is not a cryptographic signature check. The CRCs of all archived members
pass. The extraction checks paths, case-insensitive collisions, symlinks and
size limits.

The successful request body is:

```json
{
  "is_car_mihome": false,
  "latest_req": {
    "api_version": 10117,
    "app_platform": "Android",
    "region": "CN",
    "plugins": [{"model": "njcuk.fitting.ad1204"}],
    "package_type": ""
  },
  "backup_req": {
    "plugins": [{"model": "njcuk.fitting.ad1204"}],
    "api_level": 111,
    "app_platform": "phone"
  }
}
```

The client sends this as the `data` JSON inside its authenticated RC4 request
envelope. This document does not publish cookies, nonces, encrypted session
material or account/device identifiers. `latest_info[0].download_url` gives the
ZIP. The download itself uses a separate unauthenticated connection. This is a
record of one successful lookup. It does not promise that the server always
returns the current package.

The local evidence is in the ignored directory
`artifacts/mihome-cn-20261015/plugin-fetch/`: `lookup-native.json`, `download.json`,
the ZIP, `extracted/`, `signature-verification.json` and `javascript/`.

## Signature verification

`android/bundle.cert` contains two EC certificates: Mijia Open, and a leaf with
subject `O=cert,C=CN`. `bundle.sign` is a 71-byte DER ECDSA signature. The Mi
Home verifier is `_m_j.d98.OooOO0O` in the downloaded host APK. Its algorithm
is:

```text
payload = SHA256(raw project.json) || SHA256(main.bundle[0:signed_length])
verify bundle.sign as SHA256withECDSA(payload), using the leaf certificate
```

If `project.json.signature > 1024`, the signed length is the smaller value of
that field and the bundle length. In other cases, the full bundle is used. This
package declares `1048576`. Thus the signature covers all 925870 bundle bytes
and the raw project JSON. The first hypothesis (main bundle only, first
certificate) failed. The byte sequence from the host code and the leaf key
verify correctly.

Each certificate signature verifies against the issuer before it. The chain
starts with the exact SPKI public key from `assets/MijiaRootCert.der` in the
host APK. Root file SHA-256:
`0efa59bd969170149136a494c735d2fabad3bddf28345c0d3435e9b337be8bbe`.
The strict Python X.509 parser rejects the algorithm encoding of the root. A
limited DER field walk gets its original SPKI bytes and does not change the
certificate. The host APK is the trust anchor of this check. It is not an
independent external root source. There is no full certificate-policy or
revocation check. This signature sequence does not cover the drawable and
resource files.

## Readable JavaScript extraction

`project.json` gives these values: package `com.cuktech.charger`, model
`njcuk.fitting.ad1204`, project version `1.1.10`, SDK API `10110`, minimum SDK
`10104` and `bundle_type=indexed-ram-bundle`. These project fields are
different from the version/package/SDK fields in the cloud response.

`main.bundle` is **not encrypted**. It is a Metro indexed React Native RAM
bundle:

- Magic `0xfb0bd1e5`.
- 10452 table slots.
- 150 populated modules.
- A 24-byte startup section.
- Code-blob base `0x146ac`.

Its SHA-256 is
`c8d56c24bfc16ebe5eb802d8ac460ae908c1a81a0c4313bc43768f9b16792d04`.
The format follows [Metro's indexed RAM writer](https://github.com/facebook/metro/blob/main/packages/metro/src/shared/output/RamBundle/as-indexed-file.js):
three little-endian u32 header words, offset/length table entries and
null-terminated code strings. Module offsets are relative to the code blob,
including the startup bytes. Empty table slots are normal.

`cuktech_pc.ram_bundle` exports readable `.js` modules, raw physical sections,
source offsets and hashes, and an index. A rebuild from only the exported
sections gives all 925870 original bytes exactly. Module ranges that are
exactly the same are treated as aliases. Partial overlaps and malformed ranges
or text are rejected. Three focused tests cover holes, aliases, roundtrip,
truncation, overlap and invalid text.

To reproduce, run this command from `scripts/`, with a new output directory:

```powershell
uv run -m cuktech_pc.ram_bundle ../artifacts/mihome-cn-20261015/plugin-fetch/extracted/android/main.bundle --output ../artifacts/mihome-cn-20261015/plugin-fetch/another-js-extraction
```

These are extracted transpiled vendor JavaScript files. They are not the
original TypeScript/JSX project sources. Nothing runs the plugin.

## Official active-protocol display labels

Module 10010, `MainPage.getC1C2ProtocolStr()`, original bundle byte `0x368a3`,
extracted `modules/module-10010.js` line 3003, defines:

| Exposed code | Official plugin display text |
| --- | --- |
| 1, 2 | `5V` |
| 3 | `QC` |
| 4 | `AFC` |
| 5 | `FCP` |
| 6 | `SCP` |
| 7 | `PD` |
| 8, 9 | `PPS` |
| 10 | `UFCS` |
| Other values | empty string |

This renderer is in use. The entry/root stack sends MainPage to module 10010.
Its four port views call the function at original bytes `0x2927b`, `0x29844`,
`0x29ec9` and `0x2a4a9` (extracted lines 1746/1783/1822/1859).
`parseC1C2ProtocolInfo()` at `0x3604f` and `parseC3AProtocolInfo()` at
`0x3647c` get each protocol from the high byte of its MIOT 2.17/2.18 half-word.
They put it into the related renderer state. The low bytes have separate
parsing.

This is **official plugin label evidence**. It is not a local negotiation
trace. It does not prove that each code can occur on each port, controller or
firmware. For example, older upstream observations called a USB-A exposed `02`
QC, but the shared plugin renderer calls `02` 5V. This document keeps that
disagreement visible and does not silently relabel all ports. The app
labels did not change in this stage.

The official plugin calls **09 PPS**, not miPPS. The Xiaomi classification and
the named miPPS enable in the firmware still do not independently prove that active 09 means miPPS.
Code 10 has a direct official UFCS display label.

## Other first findings and limits

- Module 10013 maps charger SIID 2 / PIIDs 1–21 and reset AIID 1.
- Module 10433, `PortCtlPage.parseProtocolExtend()`, confirms the C1/C2 enable
  bits 0=PD / 1=PPS / 2=UFCS and the C3/A bits 0=UFCS / 1=SCP.
- `PortCtlPage.setProtocolExtend()` at `0xd2076` builds PIID 21 again. It always
  sets C1/C2 bit 3, then writes type 5. It is not an exposed per-port miPPS
  switch. The firmware analysis names that bit separately.
- In module 10010, `parseProtocolInfo()` at `0x36c2e` names the legacy PIID 7
  bits 0=SCP / 1=miPPS / 2=UFCS. Module 10391 has the related settings page.
- The root navigation module 10007 includes these routes: port controls, screen
  settings, DischargeProtocol, DebugInfo and firmware upgrade. Route names alone
  do not show a hidden command or an additional controller flasher.
- The limited bundle-text search found no `VOOC`, `temperature`, `thermal`, literal
  Chinese temperature word or its checked escaped spelling. Six `temp` matches
  are generic fault constant names in module 10232. They are not sensor
  readings. This does not prove that the hardware has no temperature sensor.

All 151 extracted JS files parse with zero parse failures. The automated
coverage of semantic relationships is **partial**. Do not treat it as complete
understanding. The specific UI and control observations above come from direct
inspection of the source.

The download, extraction, signature check and first inventory are complete.
These documents give focused analysis:

- [Debug/upgrade routes](plugin-debug-and-upgrade-followup.md).
- [Native OTA transfer](ota-transfer-framing.md).
- The [feature/write-path audit](plugin-feature-audit-20261016.md). It
  identifies the broken reset step, the batch reply pairing, the cross-port
  protocol writes and the differences between saved preferences and controller
  state.

Hardware validation and host SDK coverage are separate work.

> **Local outputs:** paths under `artifacts/` refer to local, git-ignored files
> (downloaded vendor packages and outputs regenerated by the tools in `scripts/`).
> They are not part of this repository; hashes are recorded for reproducibility.
