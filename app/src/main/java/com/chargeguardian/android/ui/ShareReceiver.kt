package com.chargeguardian.android.ui

import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.text.SpannableString
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.chargeguardian.android.scanner.ScamDetectionEngine

/**
 * ShareReceiver — handles "Share to ChargeGuardian" from any app.
 *
 * When a user selects "Share" in WhatsApp, Gmail, Messages, etc. and picks
 * ChargeGuardian, the shared text lands here. We run a full scan and show
 * a result card with signals, risk level, and score.
 *
 * Intent: ACTION_SEND with text/plain
 */
class ShareReceiver : AppCompatActivity() {

    private val engine = ScamDetectionEngine

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val sharedText = extractSharedText()
        if (sharedText.isNullOrBlank()) {
            showEmptyState()
            return
        }

        val sender = intent.getStringExtra(Intent.EXTRA_SUBJECT) ?: "Shared text"
        val result = engine.scanSharedText(sender, sharedText)

        showResultCard(result, sharedText)
    }

    private fun extractSharedText(): String? {
        return when {
            intent?.type == "text/plain" -> intent.getStringExtra(Intent.EXTRA_TEXT)
            else -> null
        }
    }

    private fun showEmptyState() {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(48, 80, 48, 48)
        }

        val iconText = TextView(this).apply {
            text = "🛡️"
            textSize = 48f
            gravity = Gravity.CENTER
        }
        val titleText = TextView(this).apply {
            text = "ChargeGuardian Scan"
            textSize = 22f
            setTypeface(null, Typeface.BOLD)
            gravity = Gravity.CENTER
            setPadding(0, 24, 0, 8)
        }
        val subtitleText = TextView(this).apply {
            text = "Share a suspicious message or email from any app.\nTap \"Share\" → \"ChargeGuardian\" to scan it."
            textSize = 14f
            gravity = Gravity.CENTER
            setTextColor(Color.parseColor("#888888"))
            setPadding(32, 0, 32, 24)
        }
        val closeBtn = Button(this).apply {
            text = "Close"
            setOnClickListener { finish() }
            setBackgroundColor(Color.parseColor("#E0E0E0"))
            setTextColor(Color.parseColor("#333333"))
        }

        layout.addView(iconText)
        layout.addView(titleText)
        layout.addView(subtitleText)
        layout.addView(closeBtn)

        setContentView(layout)
    }

    private fun showResultCard(result: ScamDetectionEngine.ScanResult, originalText: String) {
        val scrollView = ScrollView(this)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 40, 24, 24)
        }

        // ── Risk Banner ──
        val riskColor = when (result.riskLevel) {
            "critical" -> "#EF4444"
            "high" -> "#F97316"
            "medium" -> "#EAB308"
            else -> "#22C55E"
        }
        val riskLabel = when (result.riskLevel) {
            "critical" -> "🚨 LIKELY SCAM"
            "high" -> "⚠️ SUSPICIOUS"
            "medium" -> "⚡ UNUSUAL"
            else -> "✅ LOOKS SAFE"
        }
        val bannerBg = when (result.riskLevel) {
            "critical" -> "#FEF2F2"
            "high" -> "#FFF7ED"
            "medium" -> "#FEF9C3"
            else -> "#F0FDF4"
        }

        val bannerCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor(bannerBg))
            setPadding(20, 20, 20, 20)
            this@apply.layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = 16 }
        }

        val riskTitle = TextView(this).apply {
            text = riskLabel
            textSize = 18f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor(riskColor))
            setPadding(0, 0, 0, 8)
        }
        bannerCard.addView(riskTitle)

        val scoreText = TextView(this).apply {
            text = "Risk Score: ${result.score}/100"
            textSize = 14f
            setTextColor(Color.parseColor("#666666"))
        }
        bannerCard.addView(scoreText)

        layout.addView(bannerCard)

        // ── Signal Details ──
        if (result.signals.isNotEmpty()) {
            val signalsHeader = TextView(this).apply {
                text = "What was detected:"
                textSize = 13f
                setTypeface(null, Typeface.BOLD)
                setTextColor(Color.parseColor("#444444"))
                setPadding(0, 0, 0, 8)
            }
            layout.addView(signalsHeader)

            for (signal in result.signals) {
                val signalColor = when (signal.severity) {
                    "critical" -> "#EF4444"
                    "high" -> "#F97316"
                    "medium" -> "#EAB308"
                    else -> "#999999"
                }
                val signalText = TextView(this).apply {
                    text = "● ${signal.detail}"
                    textSize = 13f
                    setTextColor(Color.parseColor(signalColor))
                    setPadding(16, 4, 0, 4)
                }
                layout.addView(signalText)
            }
        }

        // ── Text Preview ──
        val previewLabel = TextView(this).apply {
            text = "\nScanned text:"
            textSize = 12f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.parseColor("#999999"))
            setPadding(0, 16, 0, 4)
        }
        layout.addView(previewLabel)

        val previewText = TextView(this).apply {
            text = originalText.take(500)
            textSize = 12f
            setTextColor(Color.parseColor("#666666"))
            setBackgroundColor(Color.parseColor("#F5F5F5"))
            setPadding(12, 12, 12, 12)
            this@apply.layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
        layout.addView(previewText)

        // ── Footer ──
        val footerText = TextView(this).apply {
            text = "\n🛡️ ChargeGuardian — All scanning is local, no data sent anywhere."
            textSize = 10f
            setTextColor(Color.parseColor("#BBBBBB"))
            setPadding(0, 12, 0, 16)
        }
        layout.addView(footerText)

        // ── Close Button ──
        val closeBtn = Button(this).apply {
            text = "Close"
            setOnClickListener { finish() }
            setBackgroundColor(Color.parseColor("#E0E0E0"))
            setTextColor(Color.parseColor("#333333"))
            this@apply.layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
        layout.addView(closeBtn)

        scrollView.addView(layout)
        setContentView(scrollView)
    }
}
