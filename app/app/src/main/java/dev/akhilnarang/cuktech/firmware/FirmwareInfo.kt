package dev.akhilnarang.cuktech.firmware

/**
 * Public firmware metadata. It contains no account credentials.
 *
 * @property model Xiaomi model name, for example `njcuk.fitting.ad1204`.
 * @property version Firmware version in the form `X.Y.Z_NNNN`, for example `2.1.2_0073`.
 * @property url Download URL. Empty for an imported file.
 * @property md5 MD5 of the complete package, as hex.
 * @property changelog Text from Xiaomi or from the app. It can be empty.
 */
data class FirmwareInfo(val model: String, val version: String, val url: String,
                        val md5: String, val changelog: String) {
/** File name for a saved copy: `{model}-{version}.bin`. */
    val fileName: String get() = "$model-$version.bin"
}
