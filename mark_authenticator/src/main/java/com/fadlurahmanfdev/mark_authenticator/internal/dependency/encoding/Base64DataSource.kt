package com.fadlurahmanfdev.mark_authenticator.internal.dependency.encoding

internal interface Base64DataSource {
    fun encode(raw: ByteArray): String
    fun decode(encoded: String): ByteArray
}
