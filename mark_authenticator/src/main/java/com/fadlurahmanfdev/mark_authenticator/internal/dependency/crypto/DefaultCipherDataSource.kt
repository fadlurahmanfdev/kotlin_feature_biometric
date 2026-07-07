package com.fadlurahmanfdev.mark_authenticator.internal.dependency.crypto

import javax.crypto.Cipher

internal class DefaultCipherDataSource : CipherDataSource {
    override fun createCipher(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")
}
