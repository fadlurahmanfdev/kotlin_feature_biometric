package com.fadlurahmanfdev.mark_authenticator.internal.dependency.crypto

import javax.crypto.Cipher

internal interface CipherDataSource {
    fun createCipher(): Cipher
}
