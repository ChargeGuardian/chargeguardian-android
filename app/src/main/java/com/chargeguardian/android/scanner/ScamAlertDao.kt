package com.chargeguardian.android.scanner

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

/**
 * Simple persistent store for scanned SMS alerts.
 * Uses SharedPreferences (lightweight, no Room migration needed).
 */
class ScamAlertDao(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("chargeguardian_sms_alerts", Context.MODE_PRIVATE)
    private val gson = Gson()

    private val scannedIds = mutableSetOf<Long>()

    init {
        // Load existing IDs
        val idsJson = prefs.getString("scanned_ids", "[]") ?: "[]"
        val type = object : TypeToken<List<Long>>() {}.type
        val ids: List<Long> = gson.fromJson(idsJson, type)
        scannedIds.addAll(ids)
    }

    fun hasAlert(smsId: Long): Boolean = smsId in scannedIds

    fun saveAlert(smsId: Long, result: ScamDetectionEngine.ScanResult) {
        scannedIds.add(smsId)
        // Keep only the last 500 IDs
        if (scannedIds.size > 500) {
            val toRemove = scannedIds.take(scannedIds.size - 500)
            scannedIds.removeAll(toRemove.toSet())
        }
        prefs.edit().putString("scanned_ids", gson.toJson(scannedIds.toList())).apply()

        // Also save the alert details
        val alertsJson = prefs.getString("alerts", "[]") ?: "[]"
        val type = object : TypeToken<MutableList<Map<String, Any>>>() {}.type
        val alerts: MutableList<Map<String, Any>> = gson.fromJson(alertsJson, type)
        alerts.add(0, mapOf(
            "id" to smsId,
            "riskLevel" to result.riskLevel,
            "score" to result.score,
            "senderName" to result.senderName,
            "snippet" to result.snippet,
            "timestamp" to System.currentTimeMillis()
        ))
        if (alerts.size > 50) {
            while (alerts.size > 50) alerts.removeAt(alerts.size - 1)
        }
        prefs.edit().putString("alerts", gson.toJson(alerts)).apply()
    }
}
