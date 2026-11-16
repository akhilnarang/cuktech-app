package dev.akhilnarang.cuktech.proto;

/**
 * Screen timeout options with their raw MIOT 2.6 values. The 0073 lookup at 0x40476c
 * uses (value - 1) as the index. The order here is for display. The app never sends
 * enum ordinals to the charger.
 */
public enum ScreenTimeout {
    ONE_MINUTE(5, 60, "1 min"),
    FIVE_MINUTES(1, 300, "5 min"),
    TEN_MINUTES(2, 600, "10 min"),
    THIRTY_MINUTES(3, 1800, "30 min"),
    ALWAYS_ON(4, 0, "Always on");

    /** Raw MIOT 2.6 value. */
    public final int wireValue;
    /** Timeout in seconds. 0 = always on. */
    public final int seconds;
    /** Display label. */
    public final String label;

    ScreenTimeout(int wireValue, int seconds, String label) {
        this.wireValue = wireValue;
        this.seconds = seconds;
        this.label = label;
    }

    /**
     * @param value Raw MIOT 2.6 value.
     * @return The matching option, or null if the value is not known.
     */
    public static ScreenTimeout fromWireValue(int value) {
        for (ScreenTimeout option : values()) if (option.wireValue == value) return option;
        return null;
    }
}
