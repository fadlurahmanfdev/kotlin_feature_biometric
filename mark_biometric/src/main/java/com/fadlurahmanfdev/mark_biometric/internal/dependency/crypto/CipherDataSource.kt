package com.fadlurahmanfdev.mark_biometric.internal.dependency.crypto

import javax.crypto.Cipher

internal interface CipherDataSource {
    fun createCipher(): Cipher
}
