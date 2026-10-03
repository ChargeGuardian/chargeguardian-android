package com.chargeguardian.android.scanner

/**
 * Scam Detection Engine — Kotlin port of the JS scam patterns.
 * Same logic across SMS, Gmail, WhatsApp — unified risk scoring.
 * All local, no network calls, no data leaves the device.
 *
 * V2.0 — Added deep crypto protection:
 *   - Wallet address detection (BTC, ETH, SOL, TRX, XRP, LTC, DOGE)
 *   - Seed phrase theft detection (BIP39)
 *   - Crypto giveaway / doubling scams
 *   - Wallet drainer detection
 *   - Pig butchering / investment scams
 *   - Fake exchange detection
 */

object ScamDetectionEngine {

    /**
     * Set to true for Pro (full deep crypto protection).
     * Free version: basic crypto keyword only.
     */
    var isPro = false

    // ── TLD / Domain patterns ──────────────────────────────────────
    private val SUSPICIOUS_TLDS = setOf(
        "xyz", "top", "club", "click", "gq", "ml", "cf", "tk",
        "work", "link", "review", "bid", "trade", "download", "stream",
        "loan", "win", "racing", "accountant", "science", "party"
    )

    private val KNOWN_SCAM_DOMAINS = setOf(
        "paypa1-secure.xyz", "amaz0n-deals.net", "netflix-account-verify.com",
        "apple-id-reset.top", "crypto-bonus-claim.xyz", "paypa1-verify.top",
        "paypa1-alert.com", "apple-id-verify.xyz", "paypall-login.com",
        "pay-pal-verify.com", "paypal-security-center.com", "netflix-billing-alert.com",
        "irs-refund-pending.com", "chase-verify-login.com", "wellsfargo-security-check.net",
        "bitcoin-giveaway.top", "coinbase-verify-account.net", "binance-security-alert.com",
        "metamask-wallet-sync.com", "fedex-delivery-pending.com", "usps-delivery-attempt.net",
        "dhl-package-hold.com", "spotify-premium-free.xyz", "facebook-security-check.com",
        "instagram-verified-badge.com", "whatsapp-web-verify.net", "telegram-verification-bot.com",
        // ── Crypto-specific scam domains ───────────────────────────
        "metamask-verify.com", "metamask-secure.com", "metamask-restore.com",
        "walletconnect-verify.com", "walletconnect-sync.com",
        "coinbase-security.com", "coinbase-login-alert.com",
        "binance-verify-alert.com", "binance-login-verify.com",
        "trustwallet-verify.com", "trustwallet-restore.com",
        "phantom-verify.com", "phantom-restore.com", "phantom-sync.com",
        "ledger-verify.com", "ledger-restore.com", "ledger-firmware-update.com",
        "trezor-verify.com", "trezor-restore.com", "trezor-update-firmware.com",
        "pancakeswap-connect.com", "pancakeswap-airdrop.org",
        "uniswap-airdrop.com", "uniswap-claim.com",
        "opensea-verify.com", "opensea-claim-mint.com",
        "double-your-crypto.com", "crypto-reward-claim.com",
        "nft-airdrop-free.com", "nft-claim-mint.com",
        "defi-airdrop-claim.com", "defi-reward-center.com",
        "claim-token-airdrop.com", "token-distribution-event.com"
    )

    // ── Crypto wallet address regex ────────────────────────────────
    private val CRYPTO_WALLET_ADDRESS = Regex(
        """\b(bc1[ac-hj-np-z02-9]{8,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|T[a-km-zA-HJ-NP-Z1-9]{33}|r[a-km-zA-HJ-NP-Z1-9]{24,34}|[LM][a-km-zA-HJ-NP-Z1-9]{26,33}|D[a-km-zA-HJ-NP-Z1-9]{33})\b"""
    )

    // ── Pattern definitions ────────────────────────────────────────

    data class ScamPattern(val regex: Regex, val detail: String, val severity: String, val score: Int)
    data class ScanResult(
        val isScam: Boolean,
        val riskLevel: String, // "critical", "high", "medium", "low"
        val score: Int,
        val signals: List<Signal>,
        val senderName: String,
        val snippet: String
    )
    data class Signal(val detail: String, val severity: String)

    private val URGENCY_PATTERNS = listOf(
        ScamPattern(Regex("urgent", RegexOption.IGNORE_CASE), "Urgency: \"urgent\"", "medium", 6),
        ScamPattern(Regex("immediately", RegexOption.IGNORE_CASE), "Urgency: \"immediately\"", "medium", 6),
        ScamPattern(Regex("suspended", RegexOption.IGNORE_CASE), "Account suspension threat", "high", 10),
        ScamPattern(Regex("verify now", RegexOption.IGNORE_CASE), "Pressure: \"verify now\"", "high", 10),
        ScamPattern(Regex("click here", RegexOption.IGNORE_CASE), "Phishing bait: \"click here\"", "high", 10),
        ScamPattern(Regex("limited time", RegexOption.IGNORE_CASE), "Scarcity: \"limited time\"", "medium", 6),
        ScamPattern(Regex("account blocked", RegexOption.IGNORE_CASE), "Account blocked threat", "high", 10),
        ScamPattern(Regex("act now", RegexOption.IGNORE_CASE), "Pressure: \"act now\"", "medium", 6),
        ScamPattern(Regex("expires today", RegexOption.IGNORE_CASE), "Urgency: \"expires today\"", "medium", 6),
        ScamPattern(Regex("your account.*(?:will be|has been).*(?:locked|suspended|deleted|terminated)", RegexOption.IGNORE_CASE), "Account closure threat", "high", 10),
        ScamPattern(Regex("(?:security|unusual|suspicious).*(?:activity|login|sign.in|attempt)", RegexOption.IGNORE_CASE), "Fake security alert", "high", 10),
        ScamPattern(Regex("confirm.*identity", RegexOption.IGNORE_CASE), "Identity verification", "high", 10),
        ScamPattern(Regex("verify.*account", RegexOption.IGNORE_CASE), "Account verification demand", "high", 10),
        ScamPattern(Regex("reset.*password", RegexOption.IGNORE_CASE), "Password reset bait", "medium", 5),
        ScamPattern(Regex("(?:won|winner|prize|congratulations).*click", RegexOption.IGNORE_CASE), "Prize scam bait", "high", 10)
    )

    private val PAYMENT_PATTERNS = listOf(
        ScamPattern(Regex("send money", RegexOption.IGNORE_CASE), "Payment request: \"send money\"", "high", 15),
        ScamPattern(Regex("wire transfer", RegexOption.IGNORE_CASE), "Wire transfer request", "critical", 25),
        ScamPattern(Regex("gift card", RegexOption.IGNORE_CASE), "Gift card payment request", "critical", 25),
        ScamPattern(Regex("bitcoin|crypto|btc|\\beth\\b|usdt|tether", RegexOption.IGNORE_CASE), "Crypto payment request", "high", 15),
        ScamPattern(Regex("western union", RegexOption.IGNORE_CASE), "Western Union request", "critical", 25),
        ScamPattern(Regex("moneygram", RegexOption.IGNORE_CASE), "MoneyGram request", "critical", 25),
        ScamPattern(Regex("zelle", RegexOption.IGNORE_CASE), "Zelle transfer request", "medium", 8),
        ScamPattern(Regex("cashapp|venmo", RegexOption.IGNORE_CASE), "Payment app request", "medium", 8),
        ScamPattern(Regex("bank.*transfer", RegexOption.IGNORE_CASE), "Bank transfer request", "high", 15),
        ScamPattern(Regex("routing.*number", RegexOption.IGNORE_CASE), "Bank routing number request", "critical", 25),
        ScamPattern(Regex("ssn|social security", RegexOption.IGNORE_CASE), "SSN request", "critical", 30)
    )

    private val SMS_SPECIFIC_PATTERNS = listOf(
        ScamPattern(Regex("(?:package|parcel|delivery).*(?:pending|hold|fee|link)", RegexOption.IGNORE_CASE), "Fake delivery SMS", "high", 12),
        ScamPattern(Regex("(?:tax|irs).*(?:refund|owed|penalty|audit)", RegexOption.IGNORE_CASE), "Fake tax/IRS SMS", "critical", 20),
        ScamPattern(Regex("(?:bank|credit union).*(?:alert|verify|confirm|suspended)", RegexOption.IGNORE_CASE), "Fake bank SMS", "critical", 20),
        ScamPattern(Regex("(?:unsubscribe|stop2end|STOP).*[?&]?(?:ref|token|id)=", RegexOption.IGNORE_CASE), "SMS phishing with tracking params", "high", 12),
        ScamPattern(Regex("(?:free|won|winner).*(?:msg|text|reply).*(?:stop|claim)", RegexOption.IGNORE_CASE), "Premium-rate SMS bait", "high", 10),
        ScamPattern(Regex("(?:you.ve|you have) been (?:selected|chosen|picked)", RegexOption.IGNORE_CASE), "Selection scam SMS", "high", 10),
        ScamPattern(Regex("\\b\\d{6}\\b.*(?:code|pin|verify|confirm)", RegexOption.IGNORE_CASE), "Potential 2FA interception", "critical", 30)
    )

    // ── Deep Crypto Scam Patterns ─────────────────────────────────

    private val SEED_PHRASE_PATTERNS = listOf(
        ScamPattern(Regex("(?:enter|input|type|paste|provide|share|verify|import|restore).*(?:seed|recovery|secret|mnemonic|private key).*(?:phrase|words)", RegexOption.IGNORE_CASE), "Seed phrase theft attempt", "critical", 50),
        ScamPattern(Regex("(?:12|twenty.four|24).*(?:word).*(?:phrase|seed|recovery|secret)", RegexOption.IGNORE_CASE), "12/24-word recovery phrase prompt", "critical", 50),
        ScamPattern(Regex("sync.*wallet.*(?:seed|phrase|recovery|private)", RegexOption.IGNORE_CASE), "Wallet sync seed phrase scam", "critical", 50),
        ScamPattern(Regex("validate.*wallet.*(?:seed|phrase|recovery|private)", RegexOption.IGNORE_CASE), "Wallet validation seed phrase scam", "critical", 50),
        ScamPattern(Regex("restore.*wallet.*(?:seed|phrase|recovery|private)", RegexOption.IGNORE_CASE), "Wallet restore seed phrase scam", "critical", 50)
    )

    private val CRYPTO_GIVEAWAY_PATTERNS = listOf(
        ScamPattern(Regex("(?:double|triple|10x|100x).*(?:your|send|deposit).*(?:crypto|bitcoin|btc|\\beth\\b|usdt)", RegexOption.IGNORE_CASE), "Crypto doubling scam", "critical", 40),
        ScamPattern(Regex("send.*(?:btc|\\beth\\b|usdt|bitcoin|ethereum).*(?:receive|get|double|back)", RegexOption.IGNORE_CASE), "Send-to-receive crypto scam", "critical", 40),
        ScamPattern(Regex("(?:elon|musk|vitalik|buterin|cz|changpeng).*(?:giveaway|giving away|airdrop|reward)", RegexOption.IGNORE_CASE), "Celebrity crypto giveaway scam", "critical", 40),
        ScamPattern(Regex("send.*(?:0\\.\\d+).*(?:btc|\\beth\\b).*(?:and.*(?:receive|get).*(?:double|triple))", RegexOption.IGNORE_CASE), "Precise crypto doubling scam", "critical", 40),
        ScamPattern(Regex("(?:free|bonus|reward).*(?:crypto|bitcoin|btc|\\beth\\b|token).*(?:claim|receive|get)", RegexOption.IGNORE_CASE), "Free crypto claim scam", "high", 20),
        ScamPattern(Regex("(?:official|verified|trusted).*(?:giveaway|airdrop|reward).*(?:crypto|token)", RegexOption.IGNORE_CASE), "Fake official crypto giveaway", "high", 20),
        ScamPattern(Regex("(?:limited time|crypto event|massive payout).*(?:bonus|reward|claim)", RegexOption.IGNORE_CASE), "Crypto event scam", "high", 18)
    )

    private val WALLET_DRAINER_PATTERNS = listOf(
        ScamPattern(Regex("connect.*wallet.*(?:receive|claim|mint|reward|airdrop)", RegexOption.IGNORE_CASE), "Wallet drainer: connect to claim", "critical", 40),
        ScamPattern(Regex("(?:approve|sign|authorize).*(?:transaction|transfer|contract).*(?:all.*tokens|unlimited)", RegexOption.IGNORE_CASE), "Wallet drainer: unlimited approval", "critical", 45),
        ScamPattern(Regex("(?:claim|mint|reward).*(?:click|tap).*(?:connect|wallet|metamask)", RegexOption.IGNORE_CASE), "Wallet drainer: click-to-connect", "critical", 38),
        ScamPattern(Regex("(?:free|bonus).*(?:nft|mint|claim).*(?:connect|wallet|metamask)", RegexOption.IGNORE_CASE), "Free NFT wallet drainer", "high", 30)
    )

    private val PIG_BUTCHERING_PATTERNS = listOf(
        ScamPattern(Regex("(?:guaranteed|risk.free|no.risk|zero.risk).*(?:return|profit|investment|crypto)", RegexOption.IGNORE_CASE), "Guaranteed crypto returns scam", "high", 30),
        ScamPattern(Regex("(?:earn|make|generate).*\\$?\\d+(?:%|percent).*(?:daily|weekly|monthly).*(?:crypto|bitcoin|trading)", RegexOption.IGNORE_CASE), "Unrealistic crypto returns", "high", 28),
        ScamPattern(Regex("(?:secret|exclusive|insider).*(?:trading|investment|crypto|signal)", RegexOption.IGNORE_CASE), "Insider crypto trading scam", "high", 25),
        ScamPattern(Regex("(?:millionaire|rich|wealthy|financially.free).*(?:crypto|bitcoin|trading|investment)", RegexOption.IGNORE_CASE), "Get-rich-quick crypto scam", "high", 25),
        ScamPattern(Regex("(?:my.*mentor|my.*trader|my.*broker).*(?:made|earned|helped).*(?:crypto|bitcoin|profit)", RegexOption.IGNORE_CASE), "Fake crypto mentor scam", "high", 22),
        ScamPattern(Regex("(?:dm|message|whatsapp|telegram).*(?:crypto|trading|investment|signal|profit)", RegexOption.IGNORE_CASE), "DM for crypto signals scam", "high", 22)
    )

    private val FAKE_EXCHANGE_PATTERNS = listOf(
        ScamPattern(Regex("(?:deposit|fund).*(?:minimum|min).*(?:\\$?\\d+).*(?:before|to).*(?:withdraw|access|trade)", RegexOption.IGNORE_CASE), "Fake exchange: deposit to withdraw", "high", 30),
        ScamPattern(Regex("(?:withdrawal|withdraw).*(?:fee|tax|commission).*(?:must.*pay|required|need)", RegexOption.IGNORE_CASE), "Fake exchange withdrawal fee", "high", 28),
        ScamPattern(Regex("(?:account).*(?:frozen|locked|suspended|restricted).*(?:deposit|pay|fee|tax)", RegexOption.IGNORE_CASE), "Frozen account deposit scam", "high", 28),
        ScamPattern(Regex("(?:verify|kyc|identity).*(?:deposit|fee|minimum).*(?:to.*withdraw|to.*trade)", RegexOption.IGNORE_CASE), "KYC deposit scam", "high", 25)
    )

    private val BRAND_NAMES = listOf(
        "paypal", "amazon", "bank of america", "chase", "wells fargo",
        "netflix", "apple", "microsoft", "google", "instagram", "facebook",
        "whatsapp", "telegram", "coinbase", "binance", "robinhood", "irs",
        "usps", "fedex", "ups", "dhl", "uscis",
        // Crypto platforms
        "metamask", "trust wallet", "phantom", "ledger", "trezor",
        "opensea", "uniswap", "pancakeswap", "kraken", "bybit", "okx",
        "crypto.com", "blockchain.com"
    )

    private val CRYPTO_LOOKALIKE_OFFICIAL: Map<String, String> = mapOf(
        "metamask" to "metamask.io",
        "binance" to "binance.com",
        "coinbase" to "coinbase.com",
        "trustwallet" to "trustwallet.com",
        "phantom" to "phantom.app",
        "opensea" to "opensea.io",
        "uniswap" to "app.uniswap.org",
        "pancakeswap" to "pancakeswap.finance",
        "ledger" to "ledger.com",
        "trezor" to "trezor.io"
    )

    // ── Link extraction ────────────────────────────────────────────

    private val URL_REGEX = Regex("https?://[^\\s<>\"']+")

    fun extractLinks(text: String): List<String> {
        return URL_REGEX.findAll(text).map {
            it.value.replace(Regex("[.,;:!?)]+$"), "")
        }.distinct().toList()
    }

    private fun extractDomain(url: String): String {
        return try {
            java.net.URL(url).host.replace(Regex("^www\\."), "").lowercase()
        } catch (_: Exception) { "" }
    }

    // ── Main scan functions ──────────────────────────────────────

    /**
     * Scan an SMS message (includes SMS-specific patterns like fake delivery, 2FA interception).
     */
    fun scanSms(sender: String, body: String): ScanResult {
        return scan(sender, body, includeSmsSpecific = true)
    }

    /**
     * Scan notification text from any app — WhatsApp, Gmail, Messenger, etc.
     * Skips SMS-specific patterns but covers urgency, payment, brand impersonation, links.
     */
    fun scanNotification(sourceApp: String, sender: String, body: String): ScanResult {
        val result = scan(sender, body, includeSmsSpecific = false)
        // Tag with source app for context
        return result.copy(senderName = if (sender.isNotBlank()) sender else sourceApp)
    }

    /**
     * Scan arbitrary shared text — full messages, emails, links.
     * Uses all patterns for thorough analysis.
     */
    fun scanSharedText(sender: String, body: String): ScanResult {
        return scan(sender, body, includeSmsSpecific = true)
    }

    private fun scan(sender: String, body: String, includeSmsSpecific: Boolean): ScanResult {
        val signals = mutableListOf<Signal>()
        var score = 0
        val bodyLower = body.lowercase()
        val links = extractLinks(body)

        // 1. Link analysis
        for (link in links) {
            val domain = extractDomain(link)
            if (domain.isEmpty()) continue

            // Known scam domain
            if (KNOWN_SCAM_DOMAINS.any { domain == it || domain.endsWith(".$it") }) {
                signals.add(Signal("Known scam domain: $domain", "critical"))
                score += 40
            }

            // Suspicious TLD
            val tld = domain.split(".").lastOrNull() ?: ""
            if (tld in SUSPICIOUS_TLDS) {
                signals.add(Signal("Suspicious domain: $domain (.$tld)", "high"))
                score += 12
            }

            // IP address link
            if (Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}").matches(domain)) {
                signals.add(Signal("Raw IP address link: $domain", "high"))
                score += 15
            }

            // URL shorteners
            val shorteners = listOf("bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "goo.gl", "buff.ly")
            if (shorteners.any { domain == it || domain.endsWith(".$it") }) {
                signals.add(Signal("Shortened URL: $domain", "medium"))
                score += 8
            }

            // Crypto lookalike domain check (Pro only)
            if (isPro) {
                for ((keyword, official) in CRYPTO_LOOKALIKE_OFFICIAL) {
                    if (domain.contains(keyword) && domain != official && !domain.endsWith(".$official")) {
                        signals.add(Signal("Fake crypto site: $domain (looks like $official)", "critical"))
                        score += 40
                        break
                    }
                }

                // Suspicious TLD + crypto terms re-check
                if (tld in SUSPICIOUS_TLDS) {
                    val hasCryptoTerms = Regex("metamask|wallet|connect|verify|airdrop|claim|token|nft|crypto|giveaway", RegexOption.IGNORE_CASE).containsMatchIn(link)
                    if (hasCryptoTerms) {
                        signals.add(Signal("Crypto phishing on suspicious TLD: $domain", "high"))
                        score += 15
                    }
                }
            }
        }

        // 2. SMS-specific patterns
        if (includeSmsSpecific) {
            for (pattern in SMS_SPECIFIC_PATTERNS) {
                if (pattern.regex.containsMatchIn(bodyLower)) {
                    signals.add(Signal(pattern.detail, pattern.severity))
                    score += pattern.score
                    break
                }
            }
        }

        // 3. Urgency phrases
        for (pattern in URGENCY_PATTERNS) {
            if (pattern.regex.containsMatchIn(bodyLower)) {
                signals.add(Signal(pattern.detail, pattern.severity))
                score += pattern.score
                break
            }
        }

        // 4. Payment requests
        for (pattern in PAYMENT_PATTERNS) {
            if (pattern.regex.containsMatchIn(bodyLower)) {
                signals.add(Signal(pattern.detail, pattern.severity))
                score += pattern.score
                break
            }
        }

        // 4a. Deep crypto scam detection (Pro only)
        if (isPro) {
            // Seed phrase theft (highest priority)
            for (pattern in SEED_PHRASE_PATTERNS) {
                if (pattern.regex.containsMatchIn(bodyLower)) {
                    signals.add(Signal(pattern.detail, pattern.severity))
                    score += pattern.score
                    break
                }
            }

            // Crypto giveaway scams
            for (pattern in CRYPTO_GIVEAWAY_PATTERNS) {
                if (pattern.regex.containsMatchIn(bodyLower)) {
                    signals.add(Signal(pattern.detail, pattern.severity))
                    score += pattern.score
                    break
                }
            }

            // Wallet drainer scams
            for (pattern in WALLET_DRAINER_PATTERNS) {
                if (pattern.regex.containsMatchIn(bodyLower)) {
                    signals.add(Signal(pattern.detail, pattern.severity))
                    score += pattern.score
                    break
                }
            }

            // Pig butchering / investment scams
            for (pattern in PIG_BUTCHERING_PATTERNS) {
                if (pattern.regex.containsMatchIn(bodyLower)) {
                    signals.add(Signal(pattern.detail, pattern.severity))
                    score += pattern.score
                    break
                }
            }

            // Fake exchange scams
            for (pattern in FAKE_EXCHANGE_PATTERNS) {
                if (pattern.regex.containsMatchIn(bodyLower)) {
                    signals.add(Signal(pattern.detail, pattern.severity))
                    score += pattern.score
                    break
                }
            }

            // Wallet address + transfer language
            val walletAddressMatch = CRYPTO_WALLET_ADDRESS.find(body)
            if (walletAddressMatch != null) {
                val hasTransferLanguage = Regex("send|transfer|deposit|donate|contribute", RegexOption.IGNORE_CASE).containsMatchIn(bodyLower)
                if (hasTransferLanguage) {
                    signals.add(Signal("Crypto address with transfer request: ${walletAddressMatch.value.take(16)}...", "high"))
                    score += 25
                } else {
                    signals.add(Signal("Crypto wallet address found in message", "medium"))
                    score += 10
                }
            }
        }

        // 5. Brand impersonation
        for (brand in BRAND_NAMES) {
            if (!bodyLower.contains(brand)) continue
            val nameLower = sender.lowercase()
            val nameContainsBrand = brand.split(" ").all { nameLower.contains(it) }
            if (nameContainsBrand) {
                signals.add(Signal("\"$sender\" may be impersonating $brand", "high"))
                score += 20
            } else {
                signals.add(Signal("Mentions $brand — verify sender", "low"))
                score += 5
            }
            break
        }

        // 6. Unknown sender + suspicious
        val isUnknownSender = sender.isBlank() || sender == "Unknown" ||
            Regex("^[\\d\\s\\-()]+$").matches(sender)
        if (isUnknownSender && score >= 10) {
            signals.add(Signal("Unidentified sender with suspicious content", "medium"))
            score += 8
        }

        // Determine risk level
        val riskLevel = when {
            score >= 50 -> "critical"
            score >= 30 -> "high"
            score >= 15 -> "medium"
            else -> "low"
        }

        return ScanResult(
            isScam = score >= 15,
            riskLevel = riskLevel,
            score = score.coerceAtMost(100),
            signals = signals,
            senderName = sender,
            snippet = body.take(120)
        )
    }
}
