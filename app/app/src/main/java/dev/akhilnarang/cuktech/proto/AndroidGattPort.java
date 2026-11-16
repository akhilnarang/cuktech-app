package dev.akhilnarang.cuktech.proto;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothStatusCodes;
import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * android.bluetooth implementation of GattPort. The port posts all binder callbacks
 * again to the main-thread handler, so the state machine of the engine runs on one
 * thread. Call all methods on the main thread. The class does no logging:
 * characteristic payloads, the device MAC and credentials never go to logcat.
 *
 * <p>Writes: Android allows ONE write operation in flight at
 * a time. This includes WRITE_TYPE_NO_RESPONSE and CCCD descriptor writes.
 * Thus, every characteristic and descriptor write goes through a
 * GattWriteQueue. The next op starts only after the real
 * onCharacteristicWrite / onDescriptorWrite callback of the previous op. The port
 * reports rejections, failed statuses and completions that do not arrive through
 * onWriteFailed as a generic transport failure. It never blames the token or the MTU.
 *
 * <p>Notifications: NotificationRelay copies the payloads on the binder thread
 * at delivery time. On API 26–32 the framework stores each notification in the
 * shared characteristic object. Thus, a c.getValue() call after the thread change
 * can see the bytes of the next frame.
 *
 * <p>The characteristic lookup uses the FE95 service. For the two vendor-status
 * UUIDs it uses AF00.
 *
 * <p>Failures in connect, discoverServices, requestMtu and subscribe come back as
 * callbacks (onDisconnected(-1), onServicesDiscovered(false), onMtu(23),
 * onSubscribed(false)). The methods do not throw.
 */
public final class AndroidGattPort implements GattPort {

    private static final UUID CCCD = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");
    private static final UUID FE95_SERVICE = UUID.fromString("0000fe95-0000-1000-8000-00805f9b34fb");

    private final Context context;
    private final Handler main = new Handler(Looper.getMainLooper());
    private final NotificationRelay relay;
    private final GattWriteQueue queue;
    private GattPort.Callbacks cb;
    private BluetoothGatt gatt;
    private boolean closed;
    /** CCCD writes in flight. All CCCDs have the same UUID, so the key is the characteristic. */
    private final Map<BluetoothGattCharacteristic, String> subPending = new HashMap<>();

    /** @param context Any context. The port keeps only the application context. */
    public AndroidGattPort(Context context) {
        this.context = context.getApplicationContext();
        this.relay = new NotificationRelay(main::post, (uuid, data) -> {
            if (!closed && cb != null) cb.onNotify(uuid, data);
        });
        this.queue = new GattWriteQueue(
                this::dispatchWrite,
                new GattWriteQueue.Timer() {
                    @Override public void postDelayed(Runnable r, long ms) {
                        main.postDelayed(r, ms);
                    }

                    @Override public void cancel(Runnable r) {
                        main.removeCallbacks(r);
                    }
                },
                (uuid, reason) -> {
                    if (!closed && cb != null) cb.onWriteFailed(uuid, reason);
                });
    }

    @Override public void setCallbacks(Callbacks cb) {
        this.cb = cb;
    }

    @Override public void connect(String mac) {
        BluetoothManager bm = (BluetoothManager) context.getSystemService(Context.BLUETOOTH_SERVICE);
        BluetoothAdapter adapter = bm == null ? null : bm.getAdapter();
        if (adapter == null || !adapter.isEnabled()) {
            post(() -> { if (cb != null) cb.onDisconnected(-1); });
            return;
        }
        try {
            BluetoothDevice device = adapter.getRemoteDevice(mac);
            gatt = device.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE);
            if (gatt == null) post(() -> { if (cb != null) cb.onDisconnected(-1); });
        } catch (SecurityException | IllegalArgumentException e) {
            post(() -> { if (cb != null) cb.onDisconnected(-1); });
        }
    }

    @Override public void discoverServices() {
        boolean ok = false;
        try {
            ok = gatt != null && gatt.discoverServices();
        } catch (SecurityException e) {
            ok = false; // mid-session permission revocation: fail cleanly
        }
        if (!ok) post(() -> { if (cb != null) cb.onServicesDiscovered(false); });
    }

    @Override public void requestMtu(int mtu) {
        boolean ok = false;
        try {
            ok = gatt != null && gatt.requestMtu(mtu);
        } catch (SecurityException ignored) {
        }
        if (!ok) post(() -> { if (cb != null) cb.onMtu(23); });
    }

    @Override public void subscribe(String uuid) {
        // setCharacteristicNotification is a local registration (no GATT op);
        // the CCCD descriptor write is what enforces it on the peer and must
        // go through the serialized write queue like every other write.
        BluetoothGattCharacteristic c = findCharacteristic(uuid);
        if (c == null || gatt == null) {
            post(() -> { if (cb != null) cb.onSubscribed(uuid, false); });
            return;
        }
        try {
            if (!gatt.setCharacteristicNotification(c, true)) {
                post(() -> { if (cb != null) cb.onSubscribed(uuid, false); });
                return;
            }
            if (c.getDescriptor(CCCD) == null) {
                post(() -> { if (cb != null) cb.onSubscribed(uuid, false); });
                return;
            }
            queue.submit(uuid, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE, true);
        } catch (SecurityException e) {
            post(() -> { if (cb != null) cb.onSubscribed(uuid, false); });
        }
    }

    @Override public boolean write(String uuid, byte[] data) {
        if (closed) return false;
        return queue.submit(uuid, data, false);
    }

    @Override public boolean read(String uuid) {
        if (closed || gatt == null) return false;
        BluetoothGattCharacteristic c = findCharacteristic(uuid);
        if (c == null) return false;
        try { return gatt.readCharacteristic(c); }
        catch (SecurityException e) { return false; }
    }

    @Override public void disconnect() {
        try {
            if (gatt != null) gatt.disconnect();
        } catch (SecurityException ignored) {
        }
    }

    /** Disconnects and closes the GATT client, and closes the write queue. Later calls do nothing. */
    @Override public void close() {
        if (closed) return;
        closed = true;
        queue.close(); // no parcel goes out after the session is dead
        try {
            // close() alone can leave the link up until supervision timeout; the charger then
            // still counts the old session as logged in and rejects the next login with e2
            if (gatt != null) { gatt.disconnect(); gatt.close(); }
        } catch (SecurityException ignored) {
        } catch (Exception ignored) {
        }
        gatt = null;
    }

    // ------------------------------------------------------------- queue sink (main thread)

    private boolean dispatchWrite(GattWriteQueue.Op op) {
        if (closed || gatt == null) return false;
        try {
            BluetoothGattCharacteristic c = findCharacteristic(op.uuid);
            if (c == null) return false;
            if (op.descriptor) {
                BluetoothGattDescriptor d = c.getDescriptor(CCCD);
                if (d == null) return false;
                subPending.put(c, op.uuid);
                boolean ok;
                if (Build.VERSION.SDK_INT >= 33) {
                    // returns BluetoothStatusCodes; 0 = SUCCESS
                    ok = gatt.writeDescriptor(d, op.data) == BluetoothStatusCodes.SUCCESS;
                } else {
                    ok = d.setValue(op.data) && gatt.writeDescriptor(d);
                }
                if (!ok) subPending.remove(c);
                return ok;
            }
            int writeType = (c.getProperties() & BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE) != 0
                    ? BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
                    : BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT;
            if (Build.VERSION.SDK_INT >= 33) {
                return gatt.writeCharacteristic(c, op.data,
                        writeType) == BluetoothStatusCodes.SUCCESS;
            }
            c.setWriteType(writeType);
            // op.data is the queue's private clone: the characteristic holds
            // it until the completion callback, and the caller cannot mutate it
            c.setValue(op.data);
            return gatt.writeCharacteristic(c);
        } catch (SecurityException e) {
            return false;
        }
    }

    // ------------------------------------------------------------- binder callbacks

    private final BluetoothGattCallback callback = new BluetoothGattCallback() {
        @Override public void onCharacteristicRead(BluetoothGatt g, BluetoothGattCharacteristic c,
                                                   byte[] value, int status) {
            deliverRead(c, value, status);
        }

        @SuppressWarnings("deprecation")
        @Override public void onCharacteristicRead(BluetoothGatt g, BluetoothGattCharacteristic c, int status) {
            deliverRead(c, c.getValue(), status);
        }

        private void deliverRead(BluetoothGattCharacteristic c, byte[] value, int status) {
            byte[] snapshot = value == null ? new byte[0] : value.clone();
            String uuid = c.getUuid().toString();
            post(() -> { if (!closed && cb != null) cb.onRead(uuid, snapshot, status == BluetoothGatt.GATT_SUCCESS); });
        }

        @Override public void onConnectionStateChange(BluetoothGatt g, int status, int newState) {
            post(() -> {
                if (closed || cb == null) return;
                if (newState == BluetoothProfile.STATE_CONNECTED) cb.onConnected();
                else if (newState == BluetoothProfile.STATE_DISCONNECTED) cb.onDisconnected(status);
            });
        }

        @Override public void onServicesDiscovered(BluetoothGatt g, int status) {
            post(() -> { if (!closed && cb != null) cb.onServicesDiscovered(status == BluetoothGatt.GATT_SUCCESS); });
        }

        @Override public void onMtuChanged(BluetoothGatt g, int mtu, int status) {
            post(() -> { if (!closed && cb != null) cb.onMtu(status == BluetoothGatt.GATT_SUCCESS ? mtu : 23); });
        }

        @Override public void onCharacteristicWrite(BluetoothGatt g,
                BluetoothGattCharacteristic c, int status) {
            // drives the write queue: exactly one op completes per callback
            post(() -> {
                if (!closed) {
                    queue.onWriteResult(status == BluetoothGatt.GATT_SUCCESS);
                    if (status == BluetoothGatt.GATT_SUCCESS && cb != null) cb.onWritten(c.getUuid().toString());
                }
            });
        }

        @Override public void onDescriptorWrite(BluetoothGatt g, BluetoothGattDescriptor d, int status) {
            post(() -> {
                if (closed) return;
                // map the descriptor back to its characteristic's uuid
                String subUuid = null;
                for (Map.Entry<BluetoothGattCharacteristic, String> e : subPending.entrySet()) {
                    if (e.getKey().getDescriptor(CCCD) == d) {
                        subUuid = e.getValue();
                        subPending.remove(e.getKey());
                        break;
                    }
                }
                queue.onWriteResult(status == BluetoothGatt.GATT_SUCCESS);
                if (subUuid != null && cb != null) cb.onSubscribed(subUuid, status == BluetoothGatt.GATT_SUCCESS);
            });
        }

        @Override public void onCharacteristicChanged(BluetoothGatt g,
                BluetoothGattCharacteristic c, byte[] value) {
            // API 33+ signature: value is a per-notification array; snapshot
            // (clone) before the thread hop anyway — structural guarantee.
            relay.deliver(c.getUuid().toString(), value);
        }

        @SuppressWarnings("deprecation")
        @Override public void onCharacteristicChanged(BluetoothGatt g, BluetoothGattCharacteristic c) {
            // legacy signature (API 26–32): the shared characteristic object
            // is overwritten by the next notification — the relay clones on
            // THIS (binder) thread before posting
            relay.deliver(c.getUuid().toString(), c.getValue());
        }
    };

    // ------------------------------------------------------------- helpers

    private BluetoothGattCharacteristic findCharacteristic(String uuid) {
        if (gatt == null) return null;
        UUID service = VendorStatus.WRITE_UUID.equals(uuid) || VendorStatus.NOTIFY_UUID.equals(uuid)
                ? UUID.fromString(VendorStatus.SERVICE_UUID) : FE95_SERVICE;
        BluetoothGattService s = gatt.getService(service);
        return s == null ? null : s.getCharacteristic(UUID.fromString(uuid));
    }

    private void post(Runnable r) {
        main.post(r);
    }
}
