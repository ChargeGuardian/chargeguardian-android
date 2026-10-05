package com.chargeguardian.android.scanner

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class ScamDetectionEngineProTest {

    private var originalIsPro = false

    @Before
    fun setUp() {
        originalIsPro = ScamDetectionEngine.isPro
        ScamDetectionEngine.isPro = true
    }

    @After
    fun tearDown() {
        ScamDetectionEngine.isPro = originalIsPro
    }

    private val ethAddress = "0x1234567890abcdef1234567890abcdef12345678"
    private val btcAddress = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"

    private fun scan(body: String, sender: String = "Support") =
        ScamDetectionEngine.scanSms(sender, body)

    private fun ScamDetectionEngine.ScanResult.has(part: String) =
        signals.any { it.detail.contains(part) }

    private fun ScamDetectionEngine.ScanResult.alerts() =
        riskLevel == "high" || riskLevel == "critical"

    @Test
    fun seedPhraseRequestIsCritical() {
        val r = scan("Type your 12 word recovery phrase to verify your Ledger")
        assertEquals("critical", r.riskLevel)
        assertTrue(r.has("Seed phrase theft attempt"))
    }

    @Test
    fun twentyFourWordPromptIsCritical() {
        val r = scan("Your 24 word secret is required to continue")
        assertEquals("critical", r.riskLevel)
        assertTrue(r.has("12/24-word recovery phrase prompt"))
    }

    @Test
    fun walletSyncSeedScamIsCritical() {
        val r = scan("Sync your wallet using your recovery key")
        assertEquals("critical", r.riskLevel)
        assertTrue(r.has("Wallet sync seed phrase scam"))
    }

    @Test
    fun walletValidationSeedScamIsCritical() {
        val r = scan("Validate your wallet with your private details")
        assertEquals("critical", r.riskLevel)
        assertTrue(r.has("Wallet validation seed phrase scam"))
    }

    @Test
    fun walletRestoreSeedScamIsCritical() {
        val r = scan("Restore your wallet using your recovery code")
        assertEquals("critical", r.riskLevel)
        assertTrue(r.has("Wallet restore seed phrase scam"))
    }

    @Test
    fun onlyFirstMatchingSeedPatternScores() {
        val r = scan("Enter your seed phrase and your 24 word recovery phrase")
        assertTrue(r.has("Seed phrase theft attempt"))
        assertFalse(r.has("12/24-word"))
    }

    @Test
    fun sendToReceiveCryptoIsCritical() {
        val r = scan("Send 0.1 BTC and receive double back")
        assertEquals("critical", r.riskLevel)
        assertTrue(r.has("Send-to-receive crypto scam"))
    }

    @Test
    fun doublingYourBitcoinIsCritical() {
        val r = scan("Double your bitcoin today, send now")
        assertEquals("critical", r.riskLevel)
        assertTrue(r.has("Crypto doubling scam"))
    }

    @Test
    fun celebrityGiveawayIsCritical() {
        val r = scan("Elon Musk is giving away bitcoin")
        assertEquals("critical", r.riskLevel)
        assertTrue(r.has("Celebrity crypto giveaway scam"))
    }

    @Test
    fun freeCryptoClaimAlerts() {
        val r = scan("Free bitcoin bonus, claim now")
        assertTrue(r.has("Free crypto claim scam"))
        assertTrue(r.alerts())
    }

    @Test
    fun fakeOfficialAirdropIsFlagged() {
        val r = scan("Official airdrop, claim your token")
        assertTrue(r.isScam)
        assertTrue(r.has("Fake official crypto giveaway"))
    }

    @Test
    fun cryptoEventScamIsFlagged() {
        val r = scan("Crypto event: massive payout bonus")
        assertTrue(r.isScam)
        assertTrue(r.has("Crypto event scam"))
    }

    @Test
    fun connectWalletToClaimAlerts() {
        val r = scan("Connect your wallet to claim your reward")
        assertTrue(r.has("Wallet drainer: connect to claim"))
        assertTrue(r.alerts())
    }

    @Test
    fun unlimitedApprovalAlerts() {
        val r = scan("Approve the transaction for unlimited access")
        assertTrue(r.has("Wallet drainer: unlimited approval"))
        assertTrue(r.alerts())
    }

    @Test
    fun clickToConnectAlerts() {
        val r = scan("Mint your reward, tap to connect")
        assertTrue(r.has("Wallet drainer: click-to-connect"))
        assertTrue(r.alerts())
    }

    @Test
    fun freeNftDrainerAlerts() {
        val r = scan("Free NFT drop, claim with metamask")
        assertTrue(r.has("Free NFT wallet drainer"))
        assertTrue(r.alerts())
    }

    @Test
    fun guaranteedReturnsAlert() {
        val r = scan("Guaranteed returns on crypto investment")
        assertTrue(r.has("Guaranteed crypto returns scam"))
        assertTrue(r.alerts())
    }

    @Test
    fun unrealisticReturnsAlert() {
        val r = scan("Make 5% daily trading bitcoin")
        assertTrue(r.has("Unrealistic crypto returns"))
        assertTrue(r.alerts())
    }

    @Test
    fun insiderTradingIsFlagged() {
        val r = scan("Join our exclusive trading signals group")
        assertTrue(r.isScam)
        assertTrue(r.has("Insider crypto trading scam"))
    }

    @Test
    fun getRichQuickAlerts() {
        val r = scan("Become financially free with crypto")
        assertTrue(r.has("Get-rich-quick crypto scam"))
        assertTrue(r.alerts())
    }

    @Test
    fun fakeMentorAlerts() {
        val r = scan("My mentor earned profit with crypto")
        assertTrue(r.has("Fake crypto mentor scam"))
        assertTrue(r.alerts())
    }

    @Test
    fun dmForSignalsAlerts() {
        val r = scan("DM me on WhatsApp about crypto signals")
        assertTrue(r.has("DM for crypto signals scam"))
        assertTrue(r.alerts())
    }

    @Test
    fun depositToWithdrawAlerts() {
        val r = scan("Deposit the minimum 500 to withdraw your funds")
        assertTrue(r.has("Fake exchange: deposit to withdraw"))
        assertTrue(r.alerts())
    }

    @Test
    fun withdrawalFeeIsFlagged() {
        val r = scan("A withdrawal fee is required to release funds")
        assertTrue(r.isScam)
        assertTrue(r.has("Fake exchange withdrawal fee"))
    }

    @Test
    fun frozenAccountDepositIsFlagged() {
        val r = scan("Your account is frozen, pay the tax")
        assertTrue(r.isScam)
        assertTrue(r.has("Frozen account deposit scam"))
    }

    @Test
    fun kycDepositIsFlagged() {
        val r = scan("Complete KYC with a deposit to withdraw")
        assertTrue(r.isScam)
        assertTrue(r.has("KYC deposit scam"))
    }

    @Test
    fun bitcoinAddressWithTransferLanguageIsFlagged() {
        val r = scan("Please donate to $btcAddress")
        assertTrue(r.isScam)
        assertTrue(r.has("Crypto address with transfer request"))
    }

    @Test
    fun addressWithoutTransferLanguageIsNotedButNotFlagged() {
        val r = scan("Here is the wallet $ethAddress")
        assertTrue(r.has("Crypto wallet address found in message"))
        assertFalse(r.isScam)
    }

    @Test
    fun freeTierIgnoresWalletAddresses() {
        ScamDetectionEngine.isPro = false
        val r = scan("Send 0.5 ETH to $ethAddress")
        assertFalse(r.has("Crypto address"))
    }

    @Test
    fun cryptoLookalikeDomainIsFlagged() {
        val r = scan("see http://metamask-support.io/login", sender = "Bob")
        assertTrue(r.has("Fake crypto site: metamask-support.io"))
        assertTrue(r.alerts())
    }

    @Test
    fun officialCryptoDomainsAreNotFlagged() {
        val links = listOf(
            "https://metamask.io/download",
            "https://support.metamask.io/help",
            "https://app.uniswap.org/swap"
        )
        for (link in links) {
            val r = scan("see $link", sender = "Bob")
            assertFalse(link, r.has("Fake crypto site"))
            assertFalse(link, r.isScam)
        }
    }

    @Test
    fun knownCryptoScamDomainIsCritical() {
        val r = scan("see http://uniswap-airdrop.com/claim", sender = "Bob")
        assertEquals("critical", r.riskLevel)
        assertTrue(r.has("Known scam domain: uniswap-airdrop.com"))
    }

    @Test
    fun cryptoTermsOnSuspiciousTldAreFlaggedOnlyInPro() {
        val body = "see http://claim-airdrop.xyz/wallet"
        assertTrue(scan(body, sender = "Bob").has("Crypto phishing on suspicious TLD"))
        ScamDetectionEngine.isPro = false
        assertFalse(scan(body, sender = "Bob").has("Crypto phishing on suspicious TLD"))
    }

    @Test
    fun lookalikeCheckIsProOnly() {
        ScamDetectionEngine.isPro = false
        val r = scan("see http://metamask-support.io/login", sender = "Bob")
        assertFalse(r.has("Fake crypto site"))
    }

    @Test
    fun multipleCategoriesStack() {
        val r = scan("Connect your wallet to claim your reward. Enter your seed phrase to verify")
        assertTrue(r.has("Seed phrase theft attempt"))
        assertTrue(r.has("Wallet drainer: connect to claim"))
        assertEquals("critical", r.riskLevel)
    }

    @Test
    fun proOnlyPatternsStayOffInFreeTier() {
        val proDetails = setOf(
            "Seed phrase theft attempt", "12/24-word recovery phrase prompt",
            "Wallet sync seed phrase scam", "Wallet validation seed phrase scam",
            "Wallet restore seed phrase scam", "Crypto doubling scam",
            "Send-to-receive crypto scam", "Celebrity crypto giveaway scam",
            "Free crypto claim scam", "Fake official crypto giveaway", "Crypto event scam",
            "Wallet drainer: connect to claim", "Wallet drainer: unlimited approval",
            "Wallet drainer: click-to-connect", "Free NFT wallet drainer",
            "Guaranteed crypto returns scam", "Unrealistic crypto returns",
            "Insider crypto trading scam", "Get-rich-quick crypto scam",
            "Fake crypto mentor scam", "DM for crypto signals scam",
            "Fake exchange: deposit to withdraw", "Fake exchange withdrawal fee",
            "Frozen account deposit scam", "KYC deposit scam"
        )
        val bodies = listOf(
            "Type your 12 word recovery phrase to verify your Ledger",
            "Your 24 word secret is required to continue",
            "Double your bitcoin today, send now",
            "Elon Musk is giving away bitcoin",
            "Connect your wallet to claim your reward",
            "Approve the transaction for unlimited access",
            "Guaranteed returns on crypto investment",
            "Deposit the minimum 500 to withdraw your funds",
            "Your account is frozen, pay the tax"
        )
        ScamDetectionEngine.isPro = false
        for (body in bodies) {
            val r = scan(body)
            assertTrue(body, r.signals.none { it.detail in proDetails })
        }
    }

    @Test
    fun ordinaryChatDoesNotTriggerCryptoPatterns() {
        val bodies = listOf(
            "Hey, want to grab lunch together?",
            "please send me something and get it back",
            "free lunch together, come get it",
            "Whether the meeting is Monday or not, send me the notes",
            "See you at the meeting tomorrow"
        )
        for (body in bodies) {
            val r = scan(body, sender = "Dana")
            assertFalse(body, r.isScam)
            assertEquals(body, 0, r.score)
        }
    }

    @Test
    fun casualBitcoinMentionDoesNotReachAlertThreshold() {
        val r = scan("I bought some bitcoin yesterday, price is up", sender = "Alex")
        assertFalse(r.alerts())
    }
}
