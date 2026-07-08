package com.fadlurahmanfdev.mark_biometric.internal.dependency.encoding

import android.util.Base64

internal class AndroidBase64DataSource : Base64DataSource {
    override fun encode(raw: ByteArray): String = Base64.encodeToString(raw, Base64.NO_WRAP)
    override fun decode(encoded: String): ByteArray = Base64.decode(encoded, Base64.NO_WRAP)
}
