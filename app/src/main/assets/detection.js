// ChargeGuardian Detection Engine v1.0
// Injected into every page loaded in the ChargeGuardian browser

(function() {
    if (window.__cgLoaded) return;
    window.__cgLoaded = true;
    window.__cgConfirmed = false;
    window.__cgCancelled = false;
    window.__cgPending = null;

    // Payment button text patterns
    var PAY_PATTERNS = [
        /buy\s*now/i,
        /place\s*order/i,
        /confirm\s*(and\s*)?pay/i,
        /complete\s*purchase/i,
        /pay\s*now/i,
        /submit\s*order/i,
        /checkout/i,
        /purchase/i,
        /order\s*now/i,
        /pay\s*\$/i,
        /proceed\s*to\s*payment/i,
        /make\s*payment/i,
        /confirm\s*order/i,
        /submit\s*payment/i,
        /pay\s*with/i,
        /authorize\s*payment/i
    ];

    // Check if text matches payment button pattern
    function isPayButton(text) {
        if (!text || text.length < 3) return false;
        text = text.trim();
        return PAY_PATTERNS.some(function(p) { return p.test(text); });
    }

    // Detect payment method from page content
    function detectPaymentMethod() {
        var html = document.documentElement.innerHTML.toLowerCase();

        // PayPal
        if (html.indexOf('paypal.com') !== -1 ||
            html.indexOf('paypal-button') !== -1 ||
            html.indexOf('data-paypal') !== -1) {
            return 'paypal';
        }

        // Stripe
        if (html.indexOf('stripe.com') !== -1 ||
            html.indexOf('js.stripe.com') !== -1 ||
            document.querySelector('[data-strike]') !== null) {
            return 'stripe';
        }

        // Google Pay
        if (html.indexOf('googlepay') !== -1 ||
            html.indexOf('google pay') !== -1 ||
            html.indexOf('payments.google.com') !== -1) {
            return 'google_pay';
        }

        // Apple Pay
        if (html.indexOf('apple pay') !== -1 ||
            html.indexOf('applepayjs') !== -1) {
            return 'apple_pay';
        }

        // Credit card (look for card input fields)
        if (document.querySelector('[autocomplete*="cc"],[name*="card"],[id*="card"],[class*="card-number"]') ||
            html.indexOf('card number') !== -1 ||
            html.indexOf('cardnumber') !== -1 ||
            html.indexOf('cc-number') !== -1) {
            return 'credit_card';
        }

        return 'unknown';
    }

    // Get merchant name
    function getMerchant() {
        // Try structured data first
        var ogSite = document.querySelector('meta[property="og:site_name"]');
        if (ogSite) return ogSite.content;

        // Try document title
        var title = document.title;
        if (title) {
            // Clean up common suffixes
            title = title.replace(/\s*[-|–]\s*(official site|home|store|shop|online).*$/i, '');
            return title || window.location.hostname;
        }
        return window.location.hostname;
    }

    // Get amount if visible on page
    function detectAmount() {
        var priceElements = document.querySelectorAll(
            '[class*="total"],[class*="amount"],[class*="price"],[id*="total"],[id*="amount"]'
        );
        for (var i = 0; i < priceElements.length; i++) {
            var text = priceElements[i].textContent || '';
            var match = text.match(/[\$€£¥]\s*[\d,]+\.?\d*/);
            if (match) return match[0];
        }
        return '';
    }

    // Intercept click on payment buttons
    function interceptClick(e) {
        var btn = e.target.closest('button, input[type="submit"], a[role="button"], [onclick]');
        if (!btn) return;

        var text = (btn.textContent || btn.value || btn.getAttribute('aria-label') || '').trim();

        if (!isPayButton(text)) return;

        // If already confirmed, let it through
        if (window.__cgConfirmed) {
            window.__cgConfirmed = false;
            return;
        }

        // If cancelled, block it
        if (window.__cgCancelled) {
            e.preventDefault();
            e.stopPropagation();
            e.stopImmediatePropagation();
            window.__cgCancelled = false;
            return;
        }

        // Block the click and trigger detection
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();

        var method = detectPaymentMethod();
        var merchant = getMerchant();
        var amount = detectAmount();

        // Call Android bridge
        try {
            if (typeof ChargeGuardianBridge !== 'undefined') {
                if (amount) {
                    ChargeGuardianBridge.onPaymentDetectedWithAmount(method, merchant, amount);
                } else {
                    ChargeGuardianBridge.onPaymentDetected(method, merchant);
                }
            }
        } catch(err) {
            console.log('ChargeGuardian bridge error:', err);
        }
    }

    // Use capture phase to intercept before anything else
    document.addEventListener('click', interceptClick, true);

    // Also observe DOM for dynamically added payment buttons
    var observer = new MutationObserver(function(mutations) {
        // Re-scan periodically for new payment buttons
        // (The click handler already covers these)
    });

    observer.observe(document.body || document.documentElement, {
        childList: true,
        subtree: true
    });

    console.log('ChargeGuardian: Protection active on ' + window.location.hostname);
})();
