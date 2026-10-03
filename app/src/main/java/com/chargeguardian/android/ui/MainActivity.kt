package com.chargeguardian.android.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.navigation.fragment.NavHostFragment
import androidx.navigation.ui.setupWithNavController
import com.chargeguardian.android.BuildConfig
import com.chargeguardian.android.R
import com.chargeguardian.android.scanner.ClipboardMonitor
import com.chargeguardian.android.scanner.ScamDetectionEngine
import com.chargeguardian.android.scanner.SmsScanner
import com.google.android.material.bottomnavigation.BottomNavigationView

class MainActivity : AppCompatActivity() {

    private var smsScanner: SmsScanner? = null
    private var clipboardMonitor: ClipboardMonitor? = null

    private val smsPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val allGranted = permissions.values.all { it }
        if (allGranted) {
            startSmsScanner()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Set Pro/Free mode based on build flavor
        ScamDetectionEngine.isPro = BuildConfig.IS_PRO

        val navHostFragment = supportFragmentManager
            .findFragmentById(R.id.nav_host_fragment) as NavHostFragment
        val navController = navHostFragment.navController

        val bottomNav = findViewById<BottomNavigationView>(R.id.bottom_navigation)
        bottomNav.setupWithNavController(navController)

        // Pro: request SMS permissions + notification listener
        if (BuildConfig.IS_PRO) {
            requestSmsPermissions()
            checkNotificationListenerAccess()
        }
    }

    override fun onResume() {
        super.onResume()
        // Re-check notification access when returning from settings
        if (isNotificationListenerEnabled() && clipboardMonitor == null) {
            startClipboardMonitor()
        }
    }

    override fun onBackPressed() {
        val navHostFragment = supportFragmentManager
            .findFragmentById(R.id.nav_host_fragment) as NavHostFragment
        val currentFragment = navHostFragment.childFragmentManager.fragments.firstOrNull()

        if (currentFragment is BrowserFragment && currentFragment.canGoBack()) {
            currentFragment.goBack()
        } else {
            super.onBackPressed()
        }
    }

    override fun onDestroy() {
        smsScanner?.stop()
        clipboardMonitor?.stop()
        super.onDestroy()
    }

    // ── SMS Scanner (Pro only) ─────────────────────────────────────

    private fun requestSmsPermissions() {
        val permissions = mutableListOf<String>()

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS)
            != PackageManager.PERMISSION_GRANTED) {
            permissions.add(Manifest.permission.RECEIVE_SMS)
        }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_SMS)
            != PackageManager.PERMISSION_GRANTED) {
            permissions.add(Manifest.permission.READ_SMS)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
                permissions.add(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        if (permissions.isNotEmpty()) {
            smsPermissionLauncher.launch(permissions.toTypedArray())
        } else {
            startSmsScanner()
        }
    }

    private fun startSmsScanner() {
        smsScanner = SmsScanner(this)
        smsScanner?.start()
    }

    // ── Notification Listener (opt-in, both Free & Pro) ─────────────

    private fun isNotificationListenerEnabled(): Boolean {
        val enabledListeners = Settings.Secure.getString(
            contentResolver,
            "enabled_notification_listeners"
        ) ?: return false
        return enabledListeners.contains(packageName)
    }

    private fun checkNotificationListenerAccess() {
        if (!isNotificationListenerEnabled()) {
            showNotificationOptInDialog()
        } else {
            startClipboardMonitor()
        }
    }

    private fun showNotificationOptInDialog() {
        AlertDialog.Builder(this)
            .setTitle("Enable Auto-Scanning")
            .setMessage(
                "ChargeGuardian scans incoming notification text from WhatsApp, " +
                "Telegram, Gmail, and Messenger to detect scams before you open them.\n\n" +
                "🔒 PRIVACY: All scanning happens locally on your device using pattern " +
                "matching. No message content, notification data, or personal information " +
                "ever leaves your device or is uploaded to any server.\n\n" +
                "📋 WHAT WE READ: Only the text content of incoming notifications from " +
                "supported messaging apps. We do not access contacts, media, location, " +
                "or any other data.\n\n" +
                "This is optional. You can always use Share-to-Scan instead.\n\n" +
                "Tap 'Enable' to go to Notification Access settings, then flip the " +
                "toggle for ChargeGuardian."
            )
            .setPositiveButton("Enable") { _, _ ->
                startActivity(Intent("android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS"))
            }
            .setNegativeButton("Not Now") { _, _ ->
                // User chose manual share-to-scan only — that's fine
            }
            .show()
    }

    // ── Clipboard Monitor ──────────────────────────────────────────

    private fun startClipboardMonitor() {
        if (clipboardMonitor != null) return
        clipboardMonitor = ClipboardMonitor(this)
        clipboardMonitor?.start()
    }
}
