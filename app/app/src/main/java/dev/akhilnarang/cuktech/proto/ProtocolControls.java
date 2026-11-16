package dev.akhilnarang.cuktech.proto;

/**
 * Changes the protocol-enable bits of 0073 that were measured on hardware. It keeps
 * all other bits unchanged.
 */
public final class ProtocolControls {
    /** Mask bit numbers for each port index 0..3 (C1, C2, C3, A). */
    public static final int[][] BITS = {{0,1,2,3},{8,9,10,11},{16,17},{24,25}};
    /** Protocol label for each entry in {@link #BITS}. */
    public static final String[][] LABELS = {{"PD","PPS","UFCS","miPPS"},
            {"PD","PPS","UFCS","miPPS"},{"UFCS","SCP"},{"UFCS","SCP"}};
    private ProtocolControls() {}

    /**
     * Sets or clears one protocol bit. On C1/C2 the app keeps PPS tied to PD, like the vendor
     * plugin (the firmware does not enforce this): clearing PD also clears PPS,
     * and setting PPS also sets PD.
     *
     * @param previous Current unsigned 32-bit mask.
     * @param bit Bit number from {@link #BITS}.
     * @param enabled True to set the bit, false to clear it.
     * @return The new mask.
     * @throws IllegalArgumentException If the mask is out of range or the bit is not in
     *         {@link #BITS}.
     */
    public static long update(long previous, int bit, boolean enabled) {
        if (previous < 0 || previous > 0xffffffffL) throw new IllegalArgumentException("protocol mask");
        boolean known = false;
        for (int[] port : BITS) for (int candidate : port) if (candidate == bit) known = true;
        if (!known) throw new IllegalArgumentException("unmapped protocol bit");
        long flag = 1L << bit;
        long next = enabled ? previous | flag : previous & ~flag;
        // App policy from the vendor plugin, not a firmware rule. Change both in one mask write.
        for (int base : new int[]{0, 8}) {
            if (bit == base && !enabled) next &= ~(1L << (base + 1));
            if (bit == base + 1 && enabled) next |= 1L << base;
        }
        return next;
    }
}
