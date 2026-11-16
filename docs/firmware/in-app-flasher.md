# In-app signed-firmware installer

> **WARNING: brick risk.** Firmware installation writes the flash of the
> charger. An interruption, a power loss or an incompatible package can make
> the charger unusable. **There is no tested recovery procedure.** ROM recovery
> and an interruption during activation are not verified. This installer is not
> tested on physical hardware. Use it only if you accept that the charger can
> stop working permanently.

The CUKTECH App app installs official signed firmware without Mi Home. The
installer was introduced in 0.7.0-experimental. It uses the saved charger token.
The app accepts only official packages signed by Xiaomi. It cannot flash
modified or custom firmware. The mapped receiver is the **China AD1204
(`njcuk.fitting.ad1204`, PID 0x660e), currently running 2.1.2_0073**.

Not tested on hardware: at the time of writing, there was no physical charger update, no request to a
charger and no phone installation. ROM recovery and an interruption during
activation are not verified.

## Use

NOTE: The charger has one Bluetooth connection. When you open **Updates**, the
app closes the controller connection, so that the updater can use it.

1. Open **Updates**.
2. Get a signed package. Use one of these methods:
   - Download a signed package that your account offers.
   - Select **Import signed firmware file** and select the signed 0073 file
     that you downloaded before.

   Import and installation do not need a cloud account or the Mi Home app.
3. On the package card, select **Install with CUKTECH App**. The card also
   has an export option. If the package version is the same as the last
   observed version, the button is **Reinstall**.

   WARNING: Do not let the charger lose mains power during installation.
4. Confirm the installation.
5. Disconnect all charging devices from the charger.
6. Keep the mains power stable and keep the phone near the charger.

   The progress moves forward only when the app receives the matching
   flash-commit notifications.
7. Wait for the verification. The app disconnects, connects again, logs in and
   reads the running version.

A matching MAC or a completed transfer alone is not a success.

Saved packages stay available after you close the screen or the app. After an
interrupted transfer, you can start a retry. The retry continues the transfer
only if the charger index and the prefix CRC agree with the selected package.
If the reboot check fails, the app does not flash again automatically. A
reinstallation of the same version can confirm the version. It cannot prove
that the running image changed, because no way to read a hash of the running
image has been established.

## Package checks

`FirmwarePackage.kt` checks these items:

- The 507,904-byte staging limit.
- The R2SF header.
- The signing boundaries.
- Unique, bounded TLVs.
- The model and product ID.
- The signed version.
- The metadata checksum.

Import gets the metadata from the tag. Then it does the same signature checks.
The MD5 that import calculates is not an independent vendor checksum.

The pinned P-256 public point comes from address `0x00424f20` in the original
0073 firmware, identified by its hash. It does not come from the bytes of the
candidate package. The chain of checks is:

1. The server certificate must verify with the pinned key.
2. The developer certificate must verify with the server key.
3. The image/tag signature must verify with the developer key.

Two packaged certificates that agree only with each other are not sufficient.
This copies the recovered chain. It does not do full PKIX revocation or policy
checks, and it does not use a vendor root from an independent source.

The app rejects unsigned, modified, wrong-model, oversize and incorrectly signed
packages before it connects. Before DFU, the app does these checks:

1. It checks the advertised PID and the registered flag.
2. It logs in to the charger with the saved token.
3. It reads the current version.

The app rejects downgrades. Direct installation is not available for these
items: overseas models, receivers that run other versions, and packages for the
secondary controller. Download and export do not depend on this gate.

## Transport and activation

`FirmwareGattLink.kt` uses the Android GATT queue and the token-login crypto of
the app. A4 negotiation selects **18 reliable payload bytes**. The app lowers
the payload limit of the type-0 offer to 18. The charger echoes the next 20-byte
type-1 probe. The receiver path `0x00419658` → `0x0041ed80` → `0x0041f504` does
this exchange and selects 512-byte logical file fragments. The ATT MTU alone
does not set the reliable payload. Scripted checks cover this conservative
profile. Physical interoperability is not tested.

`FirmwareTransfer.kt` sends commands 1/2/3, then indexed fragments, then command
4 with delay 1. It does not send the optional commands 5/6/7. It uses FE95/0017
controls and FE95/0018 reliable messages, as in
[the transfer trace](ota-transfer-framing.md). Each characteristic write waits
for a real Android completion through the optional `GattPort.onWritten`
callback. Submission to the queue is not sufficient.

The app checks the ready, missing-piece and completion ACKs. Missing indices
must be unique and in range. The number of retry rounds has a limit. The app
needs two signals for completion:

- The reliable completion.
- Event-kind 2/status 0 with the **exact pending firmware index**.

The operation stops if one of these occurs:

- Bad lengths, commands or statuses.
- Out-of-range resume indices.
- Unexpected ready or completion frames.
- Queue overflows.

Command 4 comes after all committed fragments. After a success, the app
disconnects and waits five seconds. Then it tries up to six new authenticated
version reads. These retries never send the firmware again. Each operation has
a time limit, and the full update has a limit of 20 minutes.

During the transfer, a foreground service, a temporary partial wake lock and a
screen-on flag keep the transfer running. The back button does not work during
the transfer. The ViewModel continues when the screen is created again. If the
process stops or the power fails, the operation stops. There is no new rollback
guarantee. See [Receiver/ROM boundaries](ota-firmware-receiver-followup.md).

## Verification and artifacts (0.7.0 implementation, 2026-10-16)

`:app:testDebugUnitTest :app:assembleDebug` is successful. **50 Android unit
tests pass, with zero failures, errors or skips.** The tests cover these items:

- Full and short fragments.
- Verified resume, and restart after a mismatch.
- Wrong and failed commits.
- Missing-piece retry and range checks.
- Malformed envelopes.
- Negotiation.
- Mutual HMAC login.
- Rejected proofs and probes.
- Queued writes without completion.

The real kept signed package passes pinned-root validation and import. A
modified image fails, also with a recalculated metadata MD5. The real-package
integration checks skip if the ignored vendor artifact is not in the checkout.
Both checks ran in this build. These checks do not use hardware and do not
prove ROM recovery.

APK `cuktech-local-0.7.0-experimental-debug.apk` (local build, not distributed): **12,985,163 bytes**,
SHA-256 `b5ecd1936c3d390f1f2af252fb57910e5fe9a413b2c5779d046d870ae40bb6cd`.
The Android APK v2 signature verifies. It is a debug build.

Kept signed firmware:
`artifacts/firmware/njcuk.fitting.ad1204-2.1.2_0073-signed.bin`, 496,995 bytes,
SHA-256 `1724b63e797af6a76e43d61931e2361b537e653946a130d0441ca0ef9d5ed65a`.
A new public-CDN request returned HTTP 403. A fetch with the saved PC session
failed with `CloudError`. No conclusion about session expiry or about a need
for a new login is drawn from this. The verified file is still available for offline
import. Firmware, credentials, generated APKs and analysis artifacts are not in
Git.

## Findings from the official app and plugin

The useful plugin findings are these:

- The active-protocol labels.
- The named enable switches.
- The native OTA handoff.

The developer page is available only to allowlisted accounts. Its device-log
switch calls an empty method, so it does not give a working UART toggle. There
is no new plugin evidence for a Beast entry, a VOOC label or a thermal-threshold
editor. At the end, the official host only finds the MAC again. This app
replaces that step with a new authenticated version read. Sources:
[plugin follow-up](plugin-debug-and-upgrade-followup.md),
[host completion](ota-validation-recovery.md).

> **Local outputs:** paths under `artifacts/` refer to local, git-ignored files
> (downloaded vendor packages and outputs regenerated by the tools in `scripts/`).
> They are not part of this repository; hashes are recorded for reproducibility.
