# Changelog

Android app versions. All releases are experimental.

## Unreleased
- New app ID `dev.akhilnarang.cuktech`. Uninstall the old app, install this one and pair again.
- Pairing: if the charger stops the transfer before it is ready, the app now stops at once. Before, it waited 10 s.
- A saved token with a damaged format now sends you back to setup.
- PC tool: two-factor login now requests the final login step one time, not two times.
- Firmware 2.1.2_0079: diagnostics, the thermal readout, protocol switches and direct installation are now available. The startup-artwork switch stays 0073-only, because 0079 removed the artwork.
- Diagnostic requests now have 9 bytes. Firmware 2.1.2_0079 does not reply to the old 8-byte requests.

## 0.8.2
- Port cards keep a fixed size when a port negotiates again or when its power or protocol changes.

## 0.8.1
- Pairing: The app sends bind data in 18-byte fragments, as the charger expects.
  The app answers resend requests from the charger. The app stops immediately on an abort.
  Before this fix, pairing stalled on phones with a large Bluetooth MTU.
- Setup option to keep the charger in the Xiaomi account.
- "Sign out of Xiaomi" deletes only the saved cloud session.

## 0.8.0
- New dashboard layout with Overview, Session, Controls and Insights tabs.
- Session history with estimated energy and CSV export.
- Demo mode, available from setup.
- You can cancel a connection attempt.
- After you disconnect, the app does not connect again automatically.

## 0.7.x
- Experimental in-app installer for official signed firmware. It checks the signature,
  the model and downgrades. It can resume a transfer with a CRC check. After the reboot,
  it checks the version.

## 0.6.x
- Charging protocol labels per port (PD Fixed, PD PPS, miPPS, QC, AFC, FCP, SCP, UFCS)
  with raw codes, and per-port protocol switches.
- Diagnostics: internal temperature readings, controller status, holiday startup artwork.
- Correct screen-timeout values.
- Thermal monitoring snapshots.
- Background connection through a foreground service.
- Prompt for the notification permission.
- Automatic reconnect if the charger still holds a previous session.

## 0.5.x
- Power limit shown for each port.
- Fix to the replay window for replies that arrive out of order.

## 0.4.x
- First release.
- Setup: bind or fetch the token, captcha, two-factor authentication by SMS or email.
- Offline control: telemetry for each port, port switches, timers, scenes and display
  settings.
