package com.chargeguardian.android.scanner

import android.content.ClipboardManager
import android.content.Context

/**
 * Monitors clipboard for crypto wallet addresses using Android's native
 * event-driven OnPrimaryClipChangedListener — no polling, no battery drain.
 *
 * Android 10+ restricts background clipboard access. This listener fires
 * only when the app is the active foreground window, which is exactly when
 * the user is interacting with ChargeGuardian.
 */
class ClipboardMonitor(private val context: Context) {

    private var isRunning = false
    private var lastContent = ""

    private val clipListener = ClipboardManager.OnPrimaryClipChangedListener {
        if (!isRunning) return@OnPrimaryClipChangedListener
        checkClipboard()
    }

    fun start() {
        if (isRunning) return
        isRunning = true

        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        clipboard?.addPrimaryClipChangedListener(clipListener)
    }

    fun stop() {
        if (!isRunning) return
        isRunning = false

        try {
            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            clipboard?.removePrimaryClipChangedListener(clipListener)
        } catch (_: Exception) {
            // Listener may already be removed
        }
    }

    private fun checkClipboard() {
        try {
            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            val clip = clipboard?.primaryClip ?: return
            if (clip.itemCount == 0) return

            val text = clip.getItemAt(0).text?.toString() ?: return
            if (text == lastContent) return
            lastContent = text

            if (isCryptoAddress(text)) {
                val result = ScamDetectionEngine.scanSharedText(
                    "Clipboard",
                    "Crypto wallet address: ${text.take(30)}..."
                )
                if (result.isScam) {
                    ScamAlertDao(context).saveAlert(
                        System.currentTimeMillis(),
                        result
                    )
                }
            }
        } catch (_: Exception) {
            // Clipboard access may fail on some devices — silently skip
        }
    }

    private fun isCryptoAddress(text: String): Boolean {
        val trimmed = text.trim()
        // Bitcoin: legacy, SegWit, Bech32
        val btcRegex = Regex("^(1|3|bc1)[a-zA-Z0-9]{25,62}$")
        // Ethereum / EVM chains
        val ethRegex = Regex("^0x[a-fA-F0-9]{40}$")
        // Solana
        val solRegex = Regex("^[1-9A-HJ-NP-Za-km-z]{32,44}$")
        // XRP / XRPL
        val xrpRegex = Regex("^r[1-9A-HJ-NP-Za-km-z]{24,34}$")

        return btcRegex.matches(trimmed) ||
               ethRegex.matches(trimmed) ||
               solRegex.matches(trimmed) ||
               xrpRegex.matches(trimmed)
    }
}
