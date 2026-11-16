package dev.akhilnarang.cuktech.proto;

/**
 * BLE transport interface between the pure-Java protocol engine (MiController)
 * and android.bluetooth. The production implementation is AndroidGattPort.
 * Tests drive the engine through a mock. The implementation must send all
 * callbacks on one thread, one at a time.
 *
 * <p>write() returns true if the port accepted (queued) the operation for delivery.
 * The port also reports a rejection, or a later failure of the GATT operation,
 * asynchronously through Callbacks.onWriteFailed. The engine changes that into a
 * generic transport fatal error.
 *
 * <p>Characteristics are identified by their full 128-bit UUID string.
 */
public interface GattPort {

    /** Transport events. The port calls them on one thread, one at a time. */
    interface Callbacks {
        /** The GATT link is connected. */
        void onConnected();
        /**
         * The GATT link is disconnected.
         *
         * @param status Android GATT status code of the disconnect.
         */
        void onDisconnected(int status);
        /**
         * Service discovery is complete.
         *
         * @param ok True if discovery found the services.
         */
        void onServicesDiscovered(boolean ok);
        /**
         * Reports the negotiated MTU. Implementations report the effective value,
         * or the fallback value if the request failed.
         *
         * @param mtu ATT MTU in bytes.
         */
        void onMtu(int mtu);
        /**
         * A subscribe request is complete.
         *
         * @param uuid Characteristic UUID.
         * @param ok True if the CCCD write was successful.
         */
        void onSubscribed(String uuid, boolean ok);
        /**
         * Notification payload on a subscribed characteristic.
         *
         * @param uuid Characteristic UUID.
         * @param data Payload. The receiver owns this copy.
         */
        void onNotify(String uuid, byte[] data);
        /**
         * A GATT write operation failed: the stack rejected it, the status was a
         * failure, or it timed out without a completion callback. This is a generic
         * transport failure. It never means a token or MTU problem.
         *
         * @param uuid Characteristic UUID.
         * @param reason Short text for logs.
         */
        void onWriteFailed(String uuid, String reason);
        /**
         * A characteristic write completed successfully at the Android GATT layer.
         *
         * @param uuid Characteristic UUID.
         */
        default void onWritten(String uuid) {}
        /**
         * A read from {@link #read} is complete.
         *
         * @param uuid Characteristic UUID.
         * @param data Value. It is empty if the stack gave no value.
         * @param ok True if the read was successful.
         */
        default void onRead(String uuid, byte[] data, boolean ok) {}
    }

    /**
     * Sets the receiver of all transport events. Call it before {@link #connect}.
     *
     * @param cb Event receiver.
     */
    void setCallbacks(Callbacks cb);

    /**
     * Starts a connection. The result comes through onConnected or onDisconnected.
     *
     * @param mac BLE address of the charger.
     */
    void connect(String mac);

    /** Starts service discovery. The result comes through onServicesDiscovered. */
    void discoverServices();

    /**
     * Requests an ATT MTU. The result comes through onMtu.
     *
     * @param mtu Requested MTU in bytes.
     */
    void requestMtu(int mtu);
    /**
     * Optional read. The engine uses it before the serialized auth and write sequence starts.
     * The result comes through onRead.
     *
     * @param uuid Characteristic UUID.
     * @return True if the read started. The default implementation returns false.
     */
    default boolean read(String uuid) { return false; }

    /**
     * Enables notifications on a characteristic (CCCD descriptor write).
     * The result comes through onSubscribed.
     *
     * @param uuid Characteristic UUID.
     */
    void subscribe(String uuid);

    /**
     * Fire-and-forget write at the protocol level (write-command, the same as
     * upstream response=False). At the Android level the implementation puts it
     * in a queue behind the framework gate that allows one write at a time.
     *
     * @param uuid Characteristic UUID.
     * @param data Value to write. The port can keep the array until the write is done.
     * @return False if the port did not accept (queue) the write. The caller must
     *         treat this as a fatal error.
     */
    boolean write(String uuid, byte[] data);

    /** Starts a disconnect. The result comes through onDisconnected. */
    void disconnect();

    /** Releases the GATT resources. Do not use the port after this call. */
    void close();
}
