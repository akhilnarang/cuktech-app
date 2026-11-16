package dev.akhilnarang.cuktech.proto;

import java.util.ArrayDeque;

/**
 * GATT write queue that sends one write at a time.
 *
 * <p>Android BluetoothGatt allows only ONE write operation in flight at a
 * time. This includes WRITE_TYPE_NO_RESPONSE writes and CCCD descriptor writes.
 * If the framework mDeviceBusy flag is set, a new write returns
 * ERROR_GATT_WRITE_REQUEST_BUSY or false immediately. A caller that ignores the
 * return value loses the write with no error. The engine must send
 * several writes in one callback (login command + announcement, ACK +
 * next announcement, consecutive parcels). Thus, every characteristic AND
 * descriptor write goes through this FIFO queue. The queue sends the next operation
 * only after the real framework callback of the previous one
 * (onCharacteristicWrite / onDescriptorWrite) reports completion.
 *
 * <p>Rules:
 * <ul>
 * <li>No busy-spin, and a timer never means success. An op completes ONLY through
 *   onWriteResult from a real callback. The timer of each op can only FAIL it.
 * <li>The queue CLONES each submitted frame. The caller can use its buffer again, and
 *   on the legacy API the characteristic holds the array until completion.
 * <li>Bounded: at most MAX_PENDING queued ops plus one in flight. An overflow
 *   reports a transport failure. The queue does not grow.
 * <li>A dispatch rejection (stack busy or not valid) goes to the FailListener as a
 *   generic GATT failure. It never means a token or MTU problem.
 * <li>close() removes everything. The queue ignores a late completion after close.
 *   Use one instance for each connection: this is the guard against stale callbacks.
 * </ul>
 *
 * <p>Use on the main thread only. The engine and the reposted binder callbacks run
 * on the same thread.
 */
public final class GattWriteQueue {

    /** Maximum queued ops, not counting the op in flight. */
    public static final int MAX_PENDING = 32;
    private static final long OP_TIMEOUT_MS = 10_000L;

    /** One queued write. {@code data} is a private copy. */
    public static final class Op {
        public final String uuid;
        public final byte[] data;
        public final boolean descriptor;

        Op(String uuid, byte[] data, boolean descriptor) {
            this.uuid = uuid;
            this.data = data;
            this.descriptor = descriptor;
        }
    }

    /** Sends one write to the GATT stack. */
    public interface Sink {
        /**
         * Tries to start one write now.
         *
         * @param op The write. A descriptor op is a CCCD write.
         * @return False if the stack rejected it.
         */
        boolean dispatch(Op op);
    }

    /** Timer interface. Production uses a Handler. Tests use a manual clock. */
    public interface Timer {
        /**
         * @param r Task to run once on the queue thread.
         * @param ms Delay in ms.
         */
        void postDelayed(Runnable r, long ms);

        /** @param r Task to remove, if it did not run. */
        void cancel(Runnable r);
    }

    /** Gets transport-level write failures. Callers must treat them as fatal. */
    public interface FailListener {
        /**
         * @param uuid Characteristic UUID of the failed op.
         * @param reason Short text for logs.
         */
        void onWriteFailed(String uuid, String reason);
    }

    private final ArrayDeque<Op> pendingOps = new ArrayDeque<>();
    private final Sink sink;
    private final Timer timer;
    private final FailListener fail;
    private Op inFlight;
    private Runnable opTimer;
    private boolean closed;

    /**
     * @param sink Sends the writes to the GATT stack.
     * @param timer Runs the 10 s timeout of each op.
     * @param fail Gets every failure. It is called on the queue thread.
     */
    public GattWriteQueue(Sink sink, Timer timer, FailListener fail) {
        this.sink = sink;
        this.timer = timer;
        this.fail = fail;
    }

    /**
     * Adds a write and starts it if no op is in flight. The queue copies {@code data}.
     * A later rejection, failure or 10 s timeout goes to the FailListener.
     *
     * @param uuid Characteristic UUID.
     * @param data Value to write. Must not be null.
     * @param descriptor True for a CCCD descriptor write.
     * @return False if the queue is closed or full. The queue also reports this through
     *         the FailListener, and the engine changes it into a fatal error.
     */
    public boolean submit(String uuid, byte[] data, boolean descriptor) {
        if (closed) {
            fail.onWriteFailed(uuid, "queue closed");
            return false;
        }
        if (pendingOps.size() >= MAX_PENDING) {
            fail.onWriteFailed(uuid, "write queue overflow (more than " + MAX_PENDING + " pending)");
            return false;
        }
        pendingOps.add(new Op(uuid, data.clone(), descriptor));
        drain();
        return true;
    }

    private void drain() {
        while (inFlight == null && !pendingOps.isEmpty() && !closed) {
            Op op = pendingOps.poll();
            inFlight = op;
            armOpTimer(op);
            if (!sink.dispatch(op)) {
                clearOpTimer();
                inFlight = null;
                fail.onWriteFailed(op.uuid, "write rejected by GATT stack");
                return;
            }
        }
    }

    /**
     * Reports the result of the real framework callback for the op in flight. On success
     * the next op starts. The call is ignored after close or if no op is in flight.
     *
     * @param ok True if the GATT status was success.
     */
    public void onWriteResult(boolean ok) {
        if (closed || inFlight == null) return; // stale completion after close
        clearOpTimer();
        Op op = inFlight;
        inFlight = null;
        if (!ok) {
            fail.onWriteFailed(op.uuid, "write reported failure");
            return;
        }
        drain();
    }

    /** @return True if a write is waiting for its completion callback. */
    public boolean hasInFlight() {
        return inFlight != null;
    }

    /** Removes all ops and stops the timer. Later completions and submits fail or are ignored. */
    public void close() {
        closed = true;
        pendingOps.clear();
        clearOpTimer();
        inFlight = null;
    }

    private void armOpTimer(Op op) {
        clearOpTimer();
        opTimer = () -> {
            opTimer = null;
            if (closed || inFlight != op) return;
            inFlight = null;
            // the op is abandoned; a late real completion would be ignored
            // (inFlight == null), which is safe because the session is dead
            fail.onWriteFailed(op.uuid, "write timed out without a completion callback");
            drain(); // the queue itself stays usable (fresh submits dispatch)
        };
        timer.postDelayed(opTimer, OP_TIMEOUT_MS);
    }

    private void clearOpTimer() {
        if (opTimer != null) {
            timer.cancel(opTimer);
            opTimer = null;
        }
    }
}
