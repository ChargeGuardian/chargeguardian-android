package com.chargeguardian.android.scanner

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.database.ContentObserver
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Telephony
import android.telephony.SmsMessage
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

/**
 * SMS Scanner — watches incoming SMS messages via ContentObserver.
 * Analyzes each message with the ScamDetectionEngine and fires
 * notifications for suspicious messages.
 *
 * Requires: android.permission.RECEIVE_SMS
 *           android.permission.READ_SMS (for initial scan of recent messages)
 */
class SmsScanner(private val context: Context) {

    companion object {
        const val CHANNEL_ID = "chargeguardian_sms_alerts"
        const val CHANNEL_NAME = "SMS Scam Alerts"
        const val NOTIFICATION_ID_BASE = 9000
    }

    private val engine = ScamDetectionEngine
    private val handler = Handler(Looper.getMainLooper())
    private var smsObserver: ContentObserver? = null
    private var smsReceiver: BroadcastReceiver? = null

    private val alertDao = ScamAlertDao(context)

    /**
     * Start watching incoming SMS.
     */
    fun start() {
        createNotificationChannel()

        // Method 1: ContentObserver on SMS inbox (works on most devices)
        smsObserver = object : ContentObserver(handler) {
            override fun onChange(selfChange: Boolean, uri: Uri?) {
                super.onChange(selfChange, uri)
                // Scan the most recent SMS
                scanLastSms()
            }
        }
        context.contentResolver.registerContentObserver(
            Telephony.Sms.Inbox.CONTENT_URI,
            true,
            smsObserver!!
        )

        // Method 2: BroadcastReceiver for SMS_RECEIVED (backup, more reliable on some devices)
        smsReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action == Telephony.Sms.Intents.SMS_RECEIVED_ACTION) {
                    handleIncomingSms(intent)
                }
            }
        }
        val filter = IntentFilter(Telephony.Sms.Intents.SMS_RECEIVED_ACTION)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(smsReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(smsReceiver, filter)
        }

        // Initial scan of recent messages
        handler.postDelayed({ scanRecentMessages() }, 2000)

        android.util.Log.d("ChargeGuardian", "SMS Scanner started")
    }

    /**
     * Stop watching.
     */
    fun stop() {
        smsObserver?.let { context.contentResolver.unregisterContentObserver(it) }
        smsObserver = null
        smsReceiver?.let { context.unregisterReceiver(it) }
        smsReceiver = null
    }

    // ── Scanning ───────────────────────────────────────────────────

    private fun scanLastSms() {
        try {
            val cursor = context.contentResolver.query(
                Telephony.Sms.Inbox.CONTENT_URI,
                arrayOf(Telephony.Sms._ID, Telephony.Sms.ADDRESS, Telephony.Sms.BODY, Telephony.Sms.DATE),
                null, null,
                "${Telephony.Sms.DATE} DESC LIMIT 1"
            ) ?: return

            if (cursor.moveToFirst()) {
                val id = cursor.getLong(cursor.getColumnIndexOrThrow(Telephony.Sms._ID))
                val address = cursor.getString(cursor.getColumnIndexOrThrow(Telephony.Sms.ADDRESS)) ?: "Unknown"
                val body = cursor.getString(cursor.getColumnIndexOrThrow(Telephony.Sms.BODY)) ?: ""

                if (alertDao.hasAlert(id)) return // Already scanned

                val result = engine.scanSms(address, body)
                if (result.isScam && (result.riskLevel == "critical" || result.riskLevel == "high")) {
                    alertDao.saveAlert(id, result)
                    fireNotification(result)
                }
            }
            cursor.close()
        } catch (e: Exception) {
            android.util.Log.e("ChargeGuardian", "SMS scan error: ${e.message}")
        }
    }

    private fun handleIncomingSms(intent: Intent) {
        try {
            val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
            for (msg in messages) {
                val address = msg.originatingAddress ?: msg.displayOriginatingAddress ?: "Unknown"
                val body = msg.messageBody ?: ""

                val result = engine.scanSms(address, body)
                if (result.isScam && (result.riskLevel == "critical" || result.riskLevel == "high")) {
                    alertDao.saveAlert(msg.indexOnIcc.toLong(), result)
                    fireNotification(result)
                }
            }
        } catch (e: Exception) {
            android.util.Log.e("ChargeGuardian", "Incoming SMS error: ${e.message}")
        }
    }

    private fun scanRecentMessages() {
        try {
            val cursor = context.contentResolver.query(
                Telephony.Sms.Inbox.CONTENT_URI,
                arrayOf(Telephony.Sms._ID, Telephony.Sms.ADDRESS, Telephony.Sms.BODY, Telephony.Sms.DATE),
                null, null,
                "${Telephony.Sms.DATE} DESC LIMIT 20"
            ) ?: return

            while (cursor.moveToNext()) {
                val id = cursor.getLong(cursor.getColumnIndexOrThrow(Telephony.Sms._ID))
                val address = cursor.getString(cursor.getColumnIndexOrThrow(Telephony.Sms.ADDRESS)) ?: "Unknown"
                val body = cursor.getString(cursor.getColumnIndexOrThrow(Telephony.Sms.BODY)) ?: ""

                if (alertDao.hasAlert(id)) continue

                val result = engine.scanSms(address, body)
                if (result.isScam && (result.riskLevel == "critical" || result.riskLevel == "high")) {
                    alertDao.saveAlert(id, result)
                    fireNotification(result)
                }
            }
            cursor.close()
        } catch (e: Exception) {
            android.util.Log.e("ChargeGuardian", "Recent SMS scan error: ${e.message}")
        }
    }

    // ── Notifications ──────────────────────────────────────────────

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Alerts when suspicious SMS messages are detected"
                enableVibration(true)
                setShowBadge(true)
            }
            val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun fireNotification(result: ScamDetectionEngine.ScanResult) {
        try {
            val icon = when (result.riskLevel) {
                "critical" -> "🚨"
                "high" -> "⚠️"
                else -> "⚡"
            }
            val title = when (result.riskLevel) {
                "critical" -> "$icon Critical Scam SMS Detected"
                "high" -> "$icon Suspicious SMS Detected"
                else -> "$icon Unusual SMS"
            }

            val topSignal = result.signals.firstOrNull()?.detail ?: "Suspicious content"
            val sender = if (result.senderName.isNotBlank()) " from ${result.senderName}" else ""
            val preview = if (result.snippet.isNotBlank()) result.snippet.take(80) else ""

            // Intent to open app when notification tapped
            val openIntent = context.packageManager.getLaunchIntentForPackage(context.packageName)
            val pendingIntent = PendingIntent.getActivity(
                context, 0, openIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            val notification = NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle(title)
                .setContentText("$topSignal$sender")
                .setStyle(NotificationCompat.BigTextStyle()
                    .bigText("$topSignal$sender. $preview"))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .setCategory(NotificationCompat.CATEGORY_MESSAGE)
                .build()

            val notifId = (NOTIFICATION_ID_BASE + System.currentTimeMillis() % 1000).toInt()
            NotificationManagerCompat.from(context).notify(notifId, notification)
        } catch (e: Exception) {
            android.util.Log.e("ChargeGuardian", "Notification error: ${e.message}")
        }
    }
}
