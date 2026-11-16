package dev.akhilnarang.cuktech.proto;

import org.junit.Test;
import static org.junit.Assert.*;

/** MIOT set-request wire bytes. The expected frames are hand-written from the set layout in MiotProperties. */
public class MiotPropertiesTest {
    @Test public void timerUsesLittleEndianUint16WithTypedMarker() {
        assertArrayEquals(new byte[]{0x0c, 0x20, 0x34, 0x12, 0, 1, 2, 9, 0, 2, 0x30, 0x3c, 0},
                MiotProperties.encodeSetU16(0x1234, 2, 9, 60));
        assertArrayEquals(new byte[]{0x0c, 0x20, 1, 0, 0, 1, 2, 12, 0, 2, 0x30, (byte)0xff, (byte)0xff},
                MiotProperties.encodeSetU16(1, 2, 12, 65535));
    }

    @Test(expected = IllegalArgumentException.class) public void timerDoesNotWrapBeyondUint16() {
        MiotProperties.encodeSetU16(1, 2, 9, 65536);
    }

    @Test public void protocolMaskUsesUnsignedUint32WithTypedMarker() {
        assertArrayEquals(new byte[]{0x0c,0x20,2,0,0,1,2,21,0,4,0x50,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff},
                MiotProperties.encodeSetU32(2,2,21,0xffffffffL));
    }
}
