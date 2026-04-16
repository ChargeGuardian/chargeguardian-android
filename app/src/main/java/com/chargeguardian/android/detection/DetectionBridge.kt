package com.chargeguardian.android.detection

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.webkit.JavascriptInterface

data class PaymentEvent(
    val method: String,
    val merchant: String,
    val amount: String = "",
    val url: String = ""
)

class DetectionBridge(
    private val context: Context,
    private val onPaymentDetected: (PaymentEvent) -> Unit
) {
    private val handler = Handler(Looper.getMainLooper())

    @JavascriptInterface
    fun onPaymentDetected(method: String, merchant: String) {
        handler.post {
            onPaymentDetected(PaymentEvent(method = method, merchant = merchant))
        }
    }

    @JavascriptInterface
    fun onPaymentDetectedWithAmount(method: String, merchant: String, amount: String) {
        handler.post {
            onPaymentDetected(PaymentEvent(method = method, merchant = merchant, amount = amount))
        }
    }

    @JavascriptInterface
    fun isWhitelisted(domain: String): Boolean {
        val prefs = context.getSharedPreferences("chargeguardian", Context.MODE_PRIVATE)
        val whitelist = prefs.getStringSet("whitelist", emptySet()) ?: emptySet()
        return whitelist.contains(domain)
    }

    @JavascriptInterface
    fun getLanguage(): String {
        return java.util.Locale.getDefault().language
    }
}
