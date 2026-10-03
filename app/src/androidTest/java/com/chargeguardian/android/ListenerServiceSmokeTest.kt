package com.chargeguardian.android

import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.BufferedReader
import java.io.InputStreamReader

class ListenerServiceSmokeTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val pkg: String = instrumentation.targetContext.packageName
    private val component = "$pkg/com.chargeguardian.android.scanner.NotificationScanService"

    private fun shell(cmd: String): String {
        val pfd = instrumentation.uiAutomation.executeShellCommand(cmd)
        return BufferedReader(
            InputStreamReader(ParcelFileDescriptor.AutoCloseInputStream(pfd))
        ).use { it.readText() }
    }

    @Before
    fun grantListenerAccess() {
        shell("logcat -c")
        shell("cmd notification allow_listener $component")
    }

    @After
    fun revokeListenerAccess() {
        shell("cmd notification disallow_listener $component")
    }

    @Test
    fun serviceBindsAndAppSurvives() {
        var dump = ""
        val deadline = System.currentTimeMillis() + 10_000
        while (System.currentTimeMillis() < deadline) {
            dump = shell("dumpsys notification")
            if (dump.contains("NotificationScanService")) break
            Thread.sleep(500)
        }
        assertTrue(
            "NotificationScanService should be registered as a listener for $pkg.\n$dump",
            dump.contains("NotificationScanService")
        )

        val pid = shell("pidof $pkg").trim()
        assertTrue("App process should still be running (no crash). pidof='$pid'", pid.isNotEmpty())

        val crashLog = shell("logcat -d -b crash")
        assertTrue(
            "Unexpected crash for $pkg:\n$crashLog",
            !(crashLog.contains("FATAL EXCEPTION") && crashLog.contains(pkg))
        )
    }
}
