package com.chargeguardian.android.scanner

import com.chargeguardian.android.BuildConfig
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import androidx.core.app.NotificationCompat
import java.util.concurrent.ConcurrentHashMap

/**
 * NotificationListenerService — scans incoming notification previews from
 * WhatsApp, Gmail, Messenger, Telegram, and other apps for scam patterns.
 *
 * How it works:
 * - Listens for any app posting a notification with text content.
 * - Extracts title + body text from the notification.
 * - Runs it through ScamDetectionEngine.scanNotification().
 * - If critical/high, fires a ChargeGuardian alert notification.
 *
 * Privacy: All scanning is local. No text leaves the device.
 * Marketing truth: "Scans scam-like content in notifications when
 *   notification previews are available."
 *
 * User must enable this in: Settings → Accessibility → Notification Access
 */
class NotificationScanService : NotificationListenerService() {

    companion object {
        const val CHANNEL_ID = "chargeguardian_notification_scan"
        const val CHANNEL_NAME = "Notification Scan Alerts"
        const val NOTIF_ID_BASE = 8000

        // Apps we actively scan (notifications from these apps go through the engine)
        private val SCAN_PACKAGES = setOf(
            "com.whatsapp",          // WhatsApp
            "com.whatsapp.w4b",      // WhatsApp Business
            "com.google.android.gm", // Gmail
            "com.google.android.apps.messaging", // Google Messages (already scanned via SMS, but redundancy is fine)
            "org.telegram.messenger", // Telegram
            "com.facebook.orca",     // Messenger
            "com.facebook.katana",   // Facebook
            "com.instagram.android", // Instagram
            "com.twitter.android",   // X/Twitter
            "com.snapchat.android",  // Snapchat
            "com.discord",           // Discord
            "com.signal",            // Signal
            "com.viber.voip",        // Viber
            "com.skype.raider",      // Skype
            "com.linkedin.android",  // LinkedIn
            "com.reddit.frontpage",  // Reddit
        )

        // Max notifications to scan per minute per package (rate limiting)
        private val rateLimiter = ConcurrentHashMap<String, Int>()
        private const val MAX_PER_MIN = 5
    }

    private val engine = ScamDetectionEngine
    private lateinit var alertDao: ScamAlertDao

    override fun onCreate() {
        super.onCreate()
        alertDao = ScamAlertDao(applicationContext)
        createNotificationChannel()
        android.util.Log.d("ChargeGuardian", "NotificationListenerService created")
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        // Pro-only feature — skip in free version
        if (!BuildConfig.IS_PRO) return

        val packageName = sbn.packageName

        // Only scan notifications from relevant apps
        if (packageName !in SCAN_PACKAGES) return

        // Rate limit per package
        if (!checkRateLimit(packageName)) return

        // Extract notification text
        val notification = sbn.notification
        val extras = notification.extras
        val title = extras.getString(Notification.EXTRA_TITLE, "") ?: ""
        val body = extras.getString(Notification.EXTRA_TEXT, "") ?: ""
        val bigText = extras.getString(Notification.EXTRA_BIG_TEXT, "") ?: ""
        val subText = extras.getString(Notification.EXTRA_SUB_TEXT, "") ?: ""

        // Build full text to scan
        val fullText = listOf(title, body, bigText, subText)
            .filter { it.isNotBlank() }
            .joinToString(" ")

        if (fullText.isBlank() || fullText.length < 10) return

        // Deduplicate — skip if same text was recently scanned
        val hash = fullText.hashCode()
        if (alertDao.hasAlert(hash.toLong())) return

        // Use package name as the "source app" label
        val appName = getAppName(packageName)

        // Extract sender from notification extras if available
        val sender = extras.getString(Notification.EXTRA_TITLE, "") ?: appName

        // Run scan
        val result = engine.scanNotification(appName, sender, fullText)

        if (result.isScam && (result.riskLevel == "critical" || result.riskLevel == "high")) {
            alertDao.saveAlert(hash.toLong(), result)
            fireAlert(appName, result)
        }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification) {
        // Not needed — we only scan on post
    }

    // ── Helpers ─────────────────────────────────────────────────────

    private fun getAppName(packageName: String): String {
        return try {
            val pm = packageManager
            val appInfo = pm.getApplicationInfo(packageName, 0)
            pm.getApplicationLabel(appInfo).toString()
        } catch (_: Exception) {
            packageName.substringAfterLast(".")
        }
    }

    private fun checkRateLimit(packageName: String): Boolean {
        val now = System.currentTimeMillis()
        val minute = now / 60_000
        val key = "$packageName:$minute"
        val count = rateLimiter.getOrDefault(key, 0)
        if (count >= MAX_PER_MIN) return false
        rateLimiter[key] = count + 1
        // Cleanup old rate limit entries
        rateLimiter.keys.removeIf { it.endsWith(":${minute - 1}") }
        return true
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Alerts when suspicious content is detected in app notifications"
                enableVibration(true)
                setShowBadge(true)
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun fireAlert(appName: String, result: ScamDetectionEngine.ScanResult) {
        try {
            val icon = when (result.riskLevel) {
                "critical" -> "🚨"
                "high" -> "⚠️"
                else -> "⚡"
            }
            val title = when (result.riskLevel) {
                "critical" -> "$icon Suspicious content in $appName"
                "high" -> "$icon Unusual $appName message"
                else -> "$icon Note about $appName"
            }

            val topSignal = result.signals.firstOrNull()?.detail ?: "Suspicious content detected"
            val preview = result.snippet.take(80)

            val openIntent = packageManager.getLaunchIntentForPackage(packageName)
            val pendingIntent = PendingIntent.getActivity(
                this, 0, openIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            val notification = NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle(title)
                .setContentText(topSignal)
                .setStyle(NotificationCompat.BigTextStyle()
                    .bigText("$topSignal\n\n\"$preview\"\n\nSource: $appName notification • Score: ${result.score}/100"))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .setCategory(NotificationCompat.CATEGORY_MESSAGE)
                .build()

            val notifId = (NOTIF_ID_BASE + System.currentTimeMillis() % 1000).toInt()
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.notify(notifId, notification)
        } catch (e: Exception) {
            android.util.Log.e("ChargeGuardian", "Notification scan alert error: ${e.message}")
        }
    }
}
