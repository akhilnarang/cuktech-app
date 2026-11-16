package dev.akhilnarang.cuktech.proto;

/**
 * One diagnostic reply with the time when the phone received it. This time does not
 * show the age of the firmware cache. Immutable.
 */
public final class DiagnosticSnapshot {
    /** The decoded reply. */
    public final VendorStatus.Reading reading;
    /** Wall-clock receive time as display text. */
    public final String receivedAt;
    /** Receive time on the elapsed-realtime clock, in ms. */
    public final long receivedElapsedMs;

    /**
     * @param reading Decoded reply. Must not be null.
     * @param receivedAt Wall-clock receive time text. Must not be null.
     * @param receivedElapsedMs Elapsed-realtime receive time in ms, 0 or more.
     * @throws IllegalArgumentException If a parameter is null or negative.
     */
    public DiagnosticSnapshot(VendorStatus.Reading reading, String receivedAt, long receivedElapsedMs) {
        if (reading == null || receivedAt == null || receivedElapsedMs < 0)
            throw new IllegalArgumentException("invalid diagnostic snapshot");
        this.reading = reading;
        this.receivedAt = receivedAt;
        this.receivedElapsedMs = receivedElapsedMs;
    }

    /**
     * @param nowElapsedMs Current elapsed-realtime clock in ms.
     * @return Age as "N s ago", "N min ago" or "N h ago". A negative age shows as 0 s.
     */
    public String ageText(long nowElapsedMs) {
        long seconds = Math.max(0, nowElapsedMs - receivedElapsedMs) / 1000;
        if (seconds < 60) return seconds + " s ago";
        if (seconds < 3600) return seconds / 60 + " min ago";
        return seconds / 3600 + " h ago";
    }
}
