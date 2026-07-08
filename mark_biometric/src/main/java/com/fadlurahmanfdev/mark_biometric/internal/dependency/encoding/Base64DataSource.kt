package com.fadlurahmanfdev.mark_biometric.internal.dependency.encoding

internal interface Base64DataSource {
    fun encode(raw: ByteArray): String
    fun decode(encoded: String): ByteArray
}
