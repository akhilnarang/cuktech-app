package dev.akhilnarang.cuktech.firmware

/**
 * Firmware versions for which each version-specific feature is known.
 *
 * A version is in a set only when static analysis showed that the firmware code behind the
 * feature is the same as in 2.1.2_0073. See `docs/firmware/diff-0079.md`.
 */
object FirmwareSupport {
    /** Firmware 2.1.2_0073, the version of the original analysis. */
    const val V2_1_2_0073 = "2.1.2_0073"

    /** Firmware 2.1.2_0079 (November 2026). */
    const val V2_1_2_0079 = "2.1.2_0079"

    /** Vendor diagnostic snapshots (thermal, controller status, versions). */
    val DIAGNOSTICS: Set<String> = setOf(V2_1_2_0073, V2_1_2_0079)

    /** Protocol-enable switches (`PIID_PROTOCOL_CTL_EXTEND`). */
    val PROTOCOL_SWITCHES: Set<String> = setOf(V2_1_2_0073, V2_1_2_0079)

    /** Holiday startup artwork. 2.1.2_0079 removed the artwork; the flag remains but has no effect. */
    val STARTUP_ARTWORK: Set<String> = setOf(V2_1_2_0073)

    /** Running versions for which the direct install flow is known. */
    val INSTALL_RECEIVERS: Set<String> = setOf(V2_1_2_0073, V2_1_2_0079)

    /**
     * @param versions One of the sets above.
     * @return The versions as display text, for example "2.1.2_0073 or 2.1.2_0079".
     */
    fun describe(versions: Set<String>): String = versions.sorted().joinToString(" or ")
}
