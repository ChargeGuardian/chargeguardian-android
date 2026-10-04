package com.chargeguardian.android.scanner

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipboardManager
import android.content.Context
import com.chargeguardian.android.BuildConfig
import com.chargeguardian.android.R

/**
 * Transparent activity. Android only lets the focused app read the clipboard,
 * so we read it in onWindowFocusChanged, show the verdict, and close.
 */
class ClipboardScanActivity : Activity() {
    private var done = false

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (!hasFocus || done) return
        done = true

        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = cm.primaryClip
        val text = if (clip != null && clip.itemCount > 0) {
            clip.getItemAt(0).coerceToText(this)?.toString()?.trim().orEmpty()
        } else ""

        if (text.isEmpty()) {
            show(getString(R.string.clip_title_empty), getString(R.string.clip_empty))
            return
        }

        if (ClipboardMonitor(this).isCryptoAddress(text)) {
            show(getString(R.string.clip_title_wallet), getString(R.string.clip_wallet))
            return
        }

        ScamDetectionEngine.isPro = BuildConfig.IS_PRO
        val result = ScamDetectionEngine.scanSms("Clipboard", text)
        if (result.isScam) {
            val details = result.signals.take(3).joinToString("\n") { "• ${it.detail}" }
            show(getString(R.string.clip_title_risky), details)
        } else {
            show(getString(R.string.clip_title_safe), getString(R.string.clip_safe))
        }
    }

    private fun show(title: String, message: String) {
        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message)
            .setPositiveButton(R.string.clip_close) { _, _ -> finish() }
            .setOnDismissListener { finish() }
            .show()
    }
}
