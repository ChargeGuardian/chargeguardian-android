package com.chargeguardian.android.scanner

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ScamDetectionEngineTest {

    private var originalIsPro = false

    @Before
    fun setUp() {
        originalIsPro = ScamDetectionEngine.isPro
        ScamDetectionEngine.isPro = false
    }

    @After
    fun tearDown() {
        ScamDetectionEngine.isPro = originalIsPro
    }

    private fun ScamDetectionEngine.ScanResult.hasSignal(textPart: String) =
        signals.any { it.detail.contains(textPart) }

    @Test
    fun extractLinks_stripsTrailingPunctuationAndDeduplicates() {
        val links = ScamDetectionEngine.extractLinks(
            "Visit https://example.com/a, then (http://foo.bar/baz). Also https://example.com/a"
        )
        assertEquals(listOf("https://example.com/a", "http://foo.bar/baz"), links)
    }

    @Test
    fun extractLinks_returnsEmptyWhenNoLinks() {
        assertTrue(ScamDetectionEngine.extractLinks("no links here").isEmpty())
    }

    @Test
    fun plainPersonalMessageIsNotFlagged() {
        val r = ScamDetectionEngine.scanSms("Mom", "Hey are we still on for dinner tonight?")
        assertFalse(r.isScam)
        assertEquals("low", r.riskLevel)
        assertEquals(0, r.score)
    }

    @Test
    fun emptyInputDoesNotCrashAndIsNotFlagged() {
        val r = ScamDetectionEngine.scanSms("", "")
        assertFalse(r.isScam)
        assertEquals(0, r.score)
    }

    @Test
    fun snippetIsTruncatedTo120Chars() {
        val r = ScamDetectionEngine.scanSms("Dana", "a".repeat(200))
        assertEquals(120, r.snippet.length)
    }

    @Test
    fun fakeDeliverySmsWithKnownScamDomainIsCritical() {
        val r = ScamDetectionEngine.scanSms(
            "+15550001111",
            "USPS: Your package is on hold, pay the fee: http://usps-delivery-attempt.net/track"
        )
        assertTrue(r.isScam)
        assertEquals("critical", r.riskLevel)
        assertTrue(r.hasSignal("Known scam domain"))
        assertTrue(r.hasSignal("Fake delivery SMS"))
    }

    @Test
    fun fakeIrsSmsIsFlagged() {
        val r = ScamDetectionEngine.scanSms("+18005551234", "IRS: You owe a tax penalty. Pay now or face an audit.")
        assertTrue(r.isScam)
        assertTrue(r.hasSignal("Fake tax/IRS SMS"))
    }

    @Test
    fun twoFactorInterceptionIsFlaggedHigh() {
        val r = ScamDetectionEngine.scanSms(
            "+15550003333",
            "Share the code with the agent to verify your account."
        )
        assertTrue(r.isScam)
        assertTrue(r.hasSignal("Asked to share a verification code"))
    }

    @Test
    fun brandImpersonationViaOffBrandLinkIsHigh() {
        val r = ScamDetectionEngine.scanSms(
            "Amazon",
            "Your Amazon account is limited, verify now at http://amaz0n-help.xyz"
        )
        assertTrue(r.isScam)
        assertTrue(r.hasSignal("mentions amazon but links to"))
    }

    @Test
    fun subdomainOfKnownScamDomainIsCritical() {
        val r = ScamDetectionEngine.scanSms("Bob", "go to http://secure.paypa1-verify.top/x")
        assertTrue(r.isScam)
        assertEquals("critical", r.riskLevel)
        assertTrue(r.hasSignal("Known scam domain"))
    }

    @Test
    fun suspiciousTldAloneIsNotEnoughToFlag() {
        val r = ScamDetectionEngine.scanSms("Bob", "see http://example.xyz/login")
        assertTrue(r.hasSignal("Suspicious domain"))
        assertFalse(r.isScam)
    }

    @Test
    fun rawIpLinkIsFlagged() {
        val r = ScamDetectionEngine.scanSms("Bob", "see http://192.168.1.1/login")
        assertTrue(r.hasSignal("Raw IP address link"))
        assertTrue(r.isScam)
        assertEquals("medium", r.riskLevel)
    }

    @Test
    fun urlShortenerIsNotedButNotFlaggedAlone() {
        val r = ScamDetectionEngine.scanSms("Bob", "see http://bit.ly/abc")
        assertTrue(r.hasSignal("Shortened URL"))
        assertFalse(r.isScam)
    }

    @Test
    fun scanNotificationUsesSourceAppWhenSenderBlank() {
        val r = ScamDetectionEngine.scanNotification("WhatsApp", "", "hello there")
        assertEquals("WhatsApp", r.senderName)
        assertFalse(r.isScam)
    }

    @Test
    fun scanNotificationKeepsSenderWhenPresent() {
        val r = ScamDetectionEngine.scanNotification("WhatsApp", "Alice", "hello there")
        assertEquals("Alice", r.senderName)
    }

    @Test
    fun scanNotificationSkipsSmsOnlyPatterns() {
        val body = "Your package is on hold, pay the fee."
        assertTrue(ScamDetectionEngine.scanSms("Dana", body).hasSignal("Fake delivery SMS"))
        assertFalse(ScamDetectionEngine.scanNotification("Messages", "Dana", body).hasSignal("Fake delivery SMS"))
    }

    @Test
    fun freeTierSkipsDeepCryptoChecks() {
        ScamDetectionEngine.isPro = false
        val r = ScamDetectionEngine.scanSms("Support", "Enter your seed phrase to sync your wallet")
        assertFalse(r.isScam)
    }

    @Test
    fun proTierCatchesSeedPhraseTheft() {
        ScamDetectionEngine.isPro = true
        val r = ScamDetectionEngine.scanSms("Support", "Enter your seed phrase to sync your wallet")
        assertTrue(r.isScam)
        assertEquals("critical", r.riskLevel)
        assertTrue(r.hasSignal("Seed phrase theft"))
    }

    @Test
    fun proTierFlagsWalletAddressWithTransferRequest() {
        ScamDetectionEngine.isPro = true
        val r = ScamDetectionEngine.scanSms(
            "Support",
            "Send 0.5 ETH to 0x1234567890abcdef1234567890abcdef12345678"
        )
        assertTrue(r.isScam)
        assertTrue(r.hasSignal("Crypto address with transfer request"))
    }

    @Test
    fun scoreIsCappedAt100ButRiskLevelStaysCritical() {
        ScamDetectionEngine.isPro = true
        val r = ScamDetectionEngine.scanSms(
            "Support",
            "Enter your seed phrase at http://metamask-verify.com/restore now. Wire transfer gift card"
        )
        assertEquals(100, r.score)
        assertEquals("critical", r.riskLevel)
    }

    @Test
    fun ordinaryWordsContainingEthAreNotFlagged() {
        val bodies = listOf("Want to grab lunch together?", "Let me know whether that method works")
        for (body in bodies) {
            assertFalse(body, ScamDetectionEngine.scanSms("Dana", body).isScam)
        }
    }

    // ── Part 3: false-positive regression tests ───────────────────

    @Test
    fun realOtpWithDontShareIsNotFlagged() {
        val r = ScamDetectionEngine.scanSms(
            "+15550001234",
            "123456 is your verification code. Don't share it."
        )
        assertFalse(r.isScam)
    }

    @Test
    fun senderNamedChaseWithPurchaseConfirmationIsNotFlagged() {
        val r = ScamDetectionEngine.scanSms("Chase", "Your purchase of $20 was approved")
        assertFalse(r.isScam)
    }

    @Test
    fun contactNamedChaseMakingPurchaseIsNotFlagged() {
        val r = ScamDetectionEngine.scanSms("Chase", "I'll make the purchase tomorrow")
        assertFalse(r.isScam)
    }

    @Test
    fun amazonShippedWithOfficialLinkIsNotFlagged() {
        val r = ScamDetectionEngine.scanSms(
            "Amazon.com",
            "Your Amazon order has shipped https://amazon.com/track/123"
        )
        assertFalse(r.isScam)
    }

    @Test
    fun brandSubstringsInsideWordsAreNotFlagged() {
        val bodies = listOf(
            "This is the first of many",
            "We have several groups meeting",
            "The setups are complete",
            "Enable tethering on your phone",
            "I study cryptography in school"
        )
        for (body in bodies) {
            assertFalse(body, ScamDetectionEngine.scanSms("Dana", body).isScam)
        }
    }

    @Test
    fun bankTransferCompletedIsNotFlagged() {
        val r = ScamDetectionEngine.scanSms(
            "Bank",
            "Your bank transfer of $50 was completed"
        )
        assertFalse(r.isScam)
    }

    @Test
    fun giftCardDeliveredIsNotFlagged() {
        val r = ScamDetectionEngine.scanSms(
            "Store",
            "Your gift card has been delivered"
        )
        assertFalse(r.isScam)
    }

    // ── Part 3: must-flag tests ───────────────────────────────────

    @Test
    fun otpRequestReplyWithCodeIsFlagged() {
        val r = ScamDetectionEngine.scanSms(
            "+18005550123",
            "Reply with the 6-digit code we sent you"
        )
        assertTrue(r.isScam)
        assertTrue(r.hasSignal("Asked to share a verification code"))
    }

    @Test
    fun amazonSuspendedWithLookalikeLinkIsFlagged() {
        val r = ScamDetectionEngine.scanSms(
            "Amazon",
            "Amazon: account suspended, verify now http://amaz0n-help.xyz"
        )
        assertTrue(r.isScam)
    }

    @Test
    fun dhlCustomsFeeWithNonDhlLinkIsFlagged() {
        val messages = listOf(
            "DHL: your package has a customs fee, pay here http://dhl-fee-pay.xyz",
            "DHL: su paquete tiene un cargo de aduana, pague aqui http://dhl-fee-pay.xyz",
            "DHL: Ihr Paket hat eine Zollgebühr, zahlen Sie hier http://dhl-fee-pay.xyz",
            "DHL: votre colis a des frais de douane, payez ici http://dhl-fee-pay.xyz"
        )
        for (msg in messages) {
            assertTrue(msg, ScamDetectionEngine.scanSms("DHL", msg).isScam)
        }
    }

    @Test
    fun transferToSafeAccountImmediatelyIsFlaggedInFourLanguages() {
        val messages = listOf(
            "Transfer the money to the safe account immediately",
            "Transferencia urgente a la cuenta segura",
            "Dringend Geld überweisen auf das sichere Konto",
            "Virement urgent sur le compte sécurisé"
        )
        for (msg in messages) {
            assertTrue(msg, ScamDetectionEngine.scanSms("Bank", msg).isScam)
        }
    }

    @Test
    fun fakeChargeNoticeWithPhoneNumberIsFlagged() {
        val r = ScamDetectionEngine.scanSms(
            "Billing",
            "$499 was charged. If you did not authorize this, call 1-800-555-0100"
        )
        assertTrue(r.isScam)
    }
}
