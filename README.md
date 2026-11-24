# cuktech-app

Control a CUKTECH 10 Ultra (AD1204U) charger over Bluetooth without Xiaomi Home.
You can read the watts and volts of each port. You can also set port and protocol
switches, shutdown timers, scenes and display settings. Setup needs the internet one
time. After setup, the app works offline.

This project is unofficial. It is not affiliated with CUKTECH or Xiaomi. There is no
warranty. Use it at your own risk.

WARNING: The in-app firmware installer is experimental. If an update stops before it
is complete, the charger can become unusable (bricked).

| Dir | What |
|---|---|
| [`app/`](app) | Android app (Kotlin + Compose). Setup, then an offline dashboard. |
| [`scripts/`](scripts) | Python CLI (`cuktech_pc`): the same setup from a PC, plus firmware tools. |
| [`docs/`](docs) | Notes about the protocol and the firmware, from reverse engineering ([index](docs/README.md), [how-to](docs/firmware-howto.md)). |

## Why you need a Xiaomi account

These facts come from the firmware (2.1.2_0073, OnMicro OM6621Px):
- To bind, the charger needs a signature from the cloud. The firmware checks this
  signature against a Mijia root key in the firmware. You cannot forge the signature.
- After the bind, login is a local key exchange with the 12-byte token. The cloud is
  not used.
- The token is stored in the charger. If you remove the charger from the account after the
  bind, the charger keeps the token, so you can still use the charger you own.

## App

NOTE: The charger accepts only one Bluetooth connection at a time. Close Xiaomi Home
before you start.

1. Install the APK.
2. Open the app.
3. Select the charger.
4. Do the step for your case:
   - Unbound charger: Sign in with any Xiaomi account. The app binds the charger and
     keeps the token on the phone (Android Keystore). Then the app removes the charger
     from the account. You can select an option to keep the charger in the account.
   - Charger that is already bound (for example, in Xiaomi Home): Sign in with the
     account that the charger is bound to. The app reads the token from the device list
     of that account. The app does not change the account.
   - You already have the token: Select "Paste a token instead".

The app keeps your password only in memory. **Sign out of Xiaomi** deletes the saved
cloud session. **Forget charger** deletes all saved data.

Build (JDK 17, Android SDK):

```bash
cd app
./gradlew :app:assembleDebug
CUKTECH_KS_FILE=/path/to/key.keystore CUKTECH_KS_PASS=... ./gradlew :app:assembleRelease
```

Release builds are unsigned if you do not set `CUKTECH_KS_FILE`/`CUKTECH_KS_PASS`.
The default for `CUKTECH_KS_ALIAS` is `cuktech-app`.

WARNING: Sign each update with the same key as the installed app. If the key is
different, the update does not install over the old app, and you lose the saved token.

## Scripts

```bash
cd scripts
uv run -m cuktech_pc.cli scan                          # find chargers (read-only)
uv run -m cuktech_pc.cli setup --region cn             # bind an unbound charger
uv run -m cuktech_pc.cli fetch-token --region in       # token only, for an already-bound charger
uv run -m cuktech_pc.cli export-token                  # write ~/.cuktech_ble.token
```

The token file uses the format that the [ha-cuk-ble](https://github.com/zuyan9/ha-cuk-ble)
Home Assistant integration reads. For details, the safety model and recovery, see
[`scripts/README.md`](scripts/README.md).

## Regions

`cn`, `in`, `i2`, `sg`, `de`, `us`, `ru`, `tw`. Use the server where the charger is
registered. Chargers for the China market usually use `cn`.

## Legal

This project exists so that owners can use their own charger. The analysis was done for
interoperability (EU Directive 2009/24/EC Art. 5(3) and 6, 17 U.S.C. §1201(f), Indian
Copyright Act s.52(1)(ab) and (ad)). The docs record only facts that interoperability needs.

- This repository does not include vendor code, decompiled output, APKs, plugins or firmware.
- The tools do not bypass a protection measure. Firmware stays signed by the vendor. The app
  checks it against the vendor's public key before it installs it.
- The tools sign in to Xiaomi's cloud as a third-party client. This can be against the Xiaomi
  Home user agreement (for example §4.1.5), and Xiaomi can suspend accounts. You are
  responsible for the terms that apply to you.
- A firmware update or other changes can affect your warranty.
- Rights holders with concerns: please open an issue before you send a formal notice.

This is not legal advice.

## License

[Apache-2.0](LICENSE). Parts are adapted from [ha-cuk-ble](https://github.com/zuyan9/ha-cuk-ble)
(Apache-2.0), [Xiaomi-cloud-tokens-extractor](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor)
(MIT) and [hass-xiaomi-miot](https://github.com/al-one/hass-xiaomi-miot) (Apache-2.0). See
[NOTICE](NOTICE). This repository does not include vendor firmware or app binaries.
CUKTECH, Xiaomi, Mi Home and Mijia are trademarks of their owners.
