package com.chargeguardian.android.ui

import android.annotation.SuppressLint
import android.content.Context
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.webkit.*
import android.widget.EditText
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.chargeguardian.android.R
import com.chargeguardian.android.detection.DetectionBridge
import com.chargeguardian.android.detection.PaymentEvent
import com.chargeguardian.android.database.ChargeLog
import com.chargeguardian.android.database.ChargeGuardianDatabase
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kotlinx.coroutines.launch
import org.json.JSONObject

class BrowserFragment : Fragment() {

    private lateinit var webView: WebView
    private lateinit var urlBar: EditText
    private lateinit var progressBar: ProgressBar
    private lateinit var shieldIcon: ImageView
    private lateinit var detectionBridge: DetectionBridge
    private var isProtected = false

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_browser, container, false)
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        webView = view.findViewById(R.id.webView)
        urlBar = view.findViewById(R.id.urlBar)
        progressBar = view.findViewById(R.id.progressBar)
        shieldIcon = view.findViewById(R.id.shieldIcon)

        detectionBridge = DetectionBridge(requireContext()) { event ->
            showConfirmationDialog(event)
        }

        setupWebView()
        setupUrlBar()

        // Load home page
        webView.loadUrl("https://www.google.com")
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun setupWebView() {
        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            databaseEnabled = true
            loadWithOverviewMode = true
            useWideViewPort = true
            builtInZoomControls = true
            displayZoomControls = false
            userAgentString = userAgentString + " ChargeGuardian/1.0"
        }

        webView.addJavascriptInterface(detectionBridge, "ChargeGuardianBridge")
        webView.webViewClient = CGWebViewClient()
        webView.webChromeClient = CGWebChromeClient()
    }

    private fun setupUrlBar() {
        urlBar.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_GO) {
                loadUrl(urlBar.text.toString())
                true
            } else false
        }

        urlBar.setOnFocusChangeListener { _, hasFocus ->
            if (hasFocus) urlBar.selectAll()
        }
    }

    private fun loadUrl(input: String) {
        val url = when {
            input.startsWith("http://") || input.startsWith("https://") -> input
            input.contains(".") && !input.contains(" ") -> "https://$input"
            else -> "https://www.google.com/search?q=${java.net.URLEncoder.encode(input, "UTF-8")}"
        }
        webView.loadUrl(url)
        urlBar.clearFocus()
    }

    private fun injectDetectionScript() {
        try {
            val js = requireContext().assets.open("detection.js").bufferedReader().use { it.readText() }
            webView.evaluateJavascript(js, null)
        } catch (e: Exception) {
            // Fallback inline detection
            webView.evaluateJavascript(INLINE_DETECTION_JS, null)
        }
    }

    private fun showConfirmationDialog(event: PaymentEvent) {
        activity?.runOnUiThread {
            val methodLabel = when (event.method) {
                "credit_card" -> getString(R.string.method_credit_card)
                "paypal" -> getString(R.string.method_paypal)
                "google_pay" -> getString(R.string.method_google_pay)
                "stripe" -> getString(R.string.method_stripe)
                else -> event.method.replace("_", " ").replaceFirstChar { it.uppercase() }
            }

            MaterialAlertDialogBuilder(requireContext())
                .setTitle(getString(R.string.confirm_title))
                .setMessage(
                    getString(R.string.confirm_message, methodLabel, event.merchant)
                )
                .setIcon(R.drawable.ic_shield)
                .setPositiveButton(getString(R.string.confirm_yes)) { _, _ ->
                    webView.evaluateJavascript("window.__cgConfirmed = true;", null)
                    logCharge(event, confirmed = true)
                }
                .setNegativeButton(getString(R.string.confirm_no)) { dialog, _ ->
                    webView.evaluateJavascript("window.__cgCancelled = true;", null)
                    logCharge(event, confirmed = false)
                    dialog.dismiss()
                }
                .setCancelable(false)
                .show()
        }
    }

    private fun logCharge(event: PaymentEvent, confirmed: Boolean) {
        lifecycleScope.launch {
            val db = ChargeGuardianDatabase.getInstance(requireContext())
            db.chargeLogDao().insert(
                ChargeLog(
                    merchant = event.merchant,
                    method = event.method,
                    url = webView.url ?: "",
                    confirmed = confirmed,
                    timestamp = System.currentTimeMillis()
                )
            )
        }
    }

    fun canGoBack(): Boolean = webView.canGoBack()
    fun goBack() = webView.goBack()

    override fun onDestroyView() {
        webView.destroy()
        super.onDestroyView()
    }

    // WebView client that injects detection JS on each page
    inner class CGWebViewClient : WebViewClient() {
        override fun onPageFinished(view: WebView?, url: String?) {
            super.onPageFinished(view, url)
            injectDetectionScript()
            url?.let {
                activity?.runOnUiThread {
                    urlBar.setText(it)
                    // Check if page has checkout/payment elements
                    isProtected = true
                    shieldIcon.setImageResource(R.drawable.ic_shield_active)
                }
            }
        }

        override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
            // Let WebView handle all navigation
            return false
        }
    }

    inner class CGWebChromeClient : WebChromeClient() {
        override fun onProgressChanged(view: WebView?, newProgress: Int) {
            progressBar.progress = newProgress
            progressBar.visibility = if (newProgress < 100) View.VISIBLE else View.GONE
        }
    }

    companion object {
        const val INLINE_DETECTION_JS = """
            (function(){
                if(window.__cgLoaded) return;
                window.__cgLoaded = true;
                window.__cgConfirmed = false;
                window.__cgCancelled = false;

                var payPatterns = /buy\s*now|place\s*order|confirm\s*(and\s*)?pay|complete\s*purchase|pay\s*now|submit\s*order|checkout|purchase|order\s*now/i;
                var payButtons = document.querySelectorAll('button, input[type="submit"], a[role="button"], [class*="pay"], [class*="checkout"], [class*="order"], [id*="pay"], [id*="checkout"], [id*="order"]');

                payButtons.forEach(function(btn){
                    var text = (btn.textContent || btn.value || btn.getAttribute('aria-label') || '').trim();
                    if(payPatterns.test(text)){
                        btn.addEventListener('click', function(e){
                            if(window.__cgConfirmed) { window.__cgConfirmed = false; return; }
                            if(window.__cgCancelled) { e.preventDefault(); e.stopPropagation(); window.__cgCancelled = false; return; }

                            e.preventDefault();
                            e.stopPropagation();

                            // Detect payment method
                            var method = 'unknown';
                            var html = document.documentElement.innerHTML.toLowerCase();
                            if(html.indexOf('paypal') !== -1) method = 'paypal';
                            else if(html.indexOf('stripe') !== -1) method = 'stripe';
                            else if(html.indexOf('googlepay') !== -1 || html.indexOf('google pay') !== -1) method = 'google_pay';
                            else if(document.querySelector('[class*="card"],[id*="card"],[autocomplete*="cc"],[name*="card"]')) method = 'credit_card';

                            var merchant = window.location.hostname;
                            try {
                                if(typeof ChargeGuardianBridge !== 'undefined'){
                                    ChargeGuardianBridge.onPaymentDetected(method, merchant);
                                }
                            } catch(err){}
                        }, true);
                    }
                });
            })();
        """
    }
}
