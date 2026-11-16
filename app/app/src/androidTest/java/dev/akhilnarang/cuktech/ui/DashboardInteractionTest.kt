package dev.akhilnarang.cuktech.ui

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.akhilnarang.cuktech.theme.CUKTECHLocalTheme
import dev.akhilnarang.cuktech.ui.controller.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DashboardInteractionTest {
    @get:Rule val compose = createComposeRule()

    @Test fun disconnectedScreenNeverClaimsLiveOutput() {
        compose.setContent { CUKTECHLocalTheme { DashboardScreen(ControllerState()) } }
        compose.onNodeWithText("NO LIVE DATA").assertIsDisplayed()
        compose.onNodeWithText("Connect").assertIsEnabled()
        compose.onNodeWithText("LIVE", substring = false).assertDoesNotExist()
    }
}
