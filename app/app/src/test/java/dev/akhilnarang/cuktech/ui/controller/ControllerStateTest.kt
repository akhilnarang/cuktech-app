package dev.akhilnarang.cuktech.ui.controller

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Every control panel is enabled through [ControllerState.canControl]; preview must never enable it. */
class ControllerStateTest {
    private val live = ControllerState(ready = true, busy = false, stale = false)

    @Test fun liveIdleSessionCanControl() {
        assertTrue(live.canControl)
    }

    @Test fun previewNeverCanControlEvenWhenOtherwiseLive() {
        assertFalse(live.copy(preview = true).canControl)
    }

    @Test fun busyStaleOrNotReadyCannotControl() {
        assertFalse(live.copy(busy = true).canControl)
        assertFalse(live.copy(stale = true).canControl)
        assertFalse(live.copy(ready = false).canControl)
    }
}
