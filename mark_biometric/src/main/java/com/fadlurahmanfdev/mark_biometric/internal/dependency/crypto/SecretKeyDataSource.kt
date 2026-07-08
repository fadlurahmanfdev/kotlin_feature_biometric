package com.fadlurahmanfdev.mark_biometric.internal.dependency.crypto

import javax.crypto.SecretKey

internal interface SecretKeyDataSource {
    fun getSecretKey(alias: String): SecretKey?
    fun generateSecretKey(alias: String, invalidatedByBiometricEnrollment: Boolean): SecretKey
    fun deleteSecretKey(alias: String)
}
