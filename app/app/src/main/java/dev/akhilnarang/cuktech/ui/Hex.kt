package dev.akhilnarang.cuktech.ui

private val HEX24 = Regex("^[0-9A-Fa-f]{24}$")

/** Returns true if [s] is exactly 24 hex characters (a 12-byte token). */
fun isToken24(s: String) = HEX24.matches(s)

/**
 * Decodes hex text to bytes. An odd last character is ignored.
 * @throws NumberFormatException If [s] has a character that is not hex.
 */
fun hexToBytes(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
