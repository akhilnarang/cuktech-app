package dev.akhilnarang.cuktech.bind

/**
 * Fields from one Xiaomi FE95 BLE service-data advert. The app parses only the fields it needs.
 *
 * @property frameControl Frame-control word, 16 bits little-endian.
 * @property productId Product id, or null if the frame is shorter than 4 bytes.
 * @property smac Advertised MAC as "AA:BB:CC:DD:EE:FF", or null if the frame does not include it.
 */
internal class Fe95Frame(val frameControl: Int, val productId: Int?, val smac: String?) {
    /** True if frame-control bit 8 is set. The charger is then already bound. */
    val registered get() = frameControl and 0x0100 != 0

    /**
     * Compares the advertised MAC with a BLE address.
     *
     * @param address BLE address. Separators ":" and "-" are ignored, and so is the letter case.
     * @return True if the advertised MAC is the same 6 bytes as [address], in either byte order.
     *   False if the advert has no MAC.
     */
    fun smacMatches(address: String): Boolean {
        val s = smac?.replace(":", "")?.lowercase() ?: return false
        val a = address.replace(":", "").replace("-", "").lowercase()
        if (s.length != 12 || a.length != 12) return false
        return s == a || s.chunked(2).reversed().joinToString("") == a
    }
}

/** FE95 advert constants and parser for the supported AD1204U chargers. */
internal object Fe95 {
    /** pid -> model: 0x660E CN (njcuk.fitting.ad1204), 0x8AB9 overseas (njcuk.fitting.1204e). */
    val MODELS = mapOf(0x660E to "njcuk.fitting.ad1204", 0x8AB9 to "njcuk.fitting.1204e")
    const val MODEL_NAME_PREFIX = "njcuk.fitting."

    /**
     * Parses FE95 service data.
     *
     * @param d Service data for UUID 0xFE95.
     * @return The frame, or null if [d] is shorter than 2 bytes.
     */
    fun parse(d: ByteArray): Fe95Frame? {
        if (d.size < 2) return null
        val fc = u16(d, 0)
        val pid = if (d.size >= 4) u16(d, 2) else null
        // the MAC is present only when frame-control bit 4 (mac_include) is set
        val smac = if (fc and 0x0010 != 0 && d.size >= 11) {
            (10 downTo 5).joinToString(":") { "%02X".format(d[it].toInt() and 0xff) }
        } else null
        return Fe95Frame(fc, pid, smac)
    }

    private fun u16(d: ByteArray, o: Int) = (d[o].toInt() and 0xff) or ((d[o + 1].toInt() and 0xff) shl 8)
}
