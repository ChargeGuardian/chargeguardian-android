package com.chargeguardian.android.scanner

import android.content.Context

/**
 * Play Store build: no SMS access. Same API as the Direct version so shared
 * code compiles, but it does nothing.
 */
@Suppress("UNUSED_PARAMETER")
class SmsScanner(context: Context) {
    fun start() {}
    fun stop() {}
}
