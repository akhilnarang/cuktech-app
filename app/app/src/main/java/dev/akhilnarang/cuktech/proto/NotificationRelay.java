package dev.akhilnarang.cuktech.proto;

/**
 * Relays notifications from the binder thread to the main thread.
 *
 * <p>On API 26–32 the framework stores each notification in the SHARED
 * characteristic object and then calls the legacy
 * onCharacteristicChanged(g, c) callback. If the app reads c.getValue() after a thread
 * change, the next notification can overwrite the payload first. The result is a lost
 * parcel, a duplicated index or a bad tag, and a false "authentication failed".
 * This relay copies the payload at DELIVERY time, on the binder thread, and then posts.
 * Thus, a posted task can never see a changed buffer. The API 33+ callback gets a
 * separate array for each notification. The app uses the same relay for both entry
 * points, so the copy occurs on all API levels.
 */
public final class NotificationRelay {

    /** Posts a task to the target thread, for example the main Handler. */
    public interface Poster {
        void post(Runnable r);
    }

    /** Receives each notification on the target thread. */
    public interface Sink {
        void onNotify(String uuid, byte[] data);
    }

    private final Poster poster;
    private final Sink sink;

    /**
     * @param poster Posts tasks to the target thread.
     * @param sink Receives the copied payloads on that thread.
     */
    public NotificationRelay(Poster poster, Sink sink) {
        this.poster = poster;
        this.sink = sink;
    }

    /**
     * Copies the value now and posts it to the sink. Call this on the binder thread.
     *
     * @param uuid Characteristic UUID.
     * @param value Notification value. Null becomes an empty array.
     */
    public void deliver(String uuid, byte[] value) {
        final byte[] snapshot = value == null ? new byte[0] : value.clone();
        poster.post(() -> sink.onNotify(uuid, snapshot));
    }
}
