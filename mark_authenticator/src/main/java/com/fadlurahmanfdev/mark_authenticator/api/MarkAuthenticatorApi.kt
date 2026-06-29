package com.fadlurahmanfdev.mark_authenticator.api

import androidx.fragment.app.FragmentActivity
import com.fadlurahmanfdev.mark_authenticator.api.callback.SecureAuthenticationDecryptCallback
import com.fadlurahmanfdev.mark_authenticator.api.callback.SecureAuthenticationEncryptCallback
import com.fadlurahmanfdev.mark_authenticator.api.callback.WeakAuthenticationCallback
import com.fadlurahmanfdev.mark_authenticator.model.MarkAuthenticationStatus
import com.fadlurahmanfdev.mark_authenticator.model.MarkAuthenticatorMethod
import javax.crypto.Cipher
import javax.crypto.SecretKey

/**
 * Public contract used by applications integrating Mark Authenticator.
 */
interface MarkAuthenticatorApi {
    /**
     * Builds a cipher used for secure biometric encryption/decryption.
     */
    fun cipher(): Cipher

    /**
     * Returns a registered secret key by [alias], or null when it does not exist.
     */
    fun getSecretKey(alias: String): SecretKey?

    /**
     * Generates a secret key in Android KeyStore.
     *
     * @param alias unique key identifier.
     * @param invalidatedByBiometricEnrollment true to invalidate key when biometric enrollment changes.
     */
    fun generateSecretKey(alias: String, invalidatedByBiometricEnrollment: Boolean = false): SecretKey

    /**
     * Deletes a secret key by [alias]. No-op if key does not exist.
     */
    fun deleteSecretKey(alias: String)

    /**
     * Returns true when fingerprint hardware is available.
     */
    fun isDeviceSupportFingerprint(): Boolean

    /**
     * Returns true when face biometric hardware is available.
     */
    fun isDeviceSupportFaceAuth(): Boolean

    /**
     * Returns true when the device supports at least one biometric method.
     */
    fun isDeviceSupportBiometric(): Boolean

    /**
     * Returns true when at least one biometric credential is enrolled.
     */
    fun isBiometricEnrolled(): Boolean

    /**
     * Returns true when device credential (PIN/pattern/password) is enrolled.
     */
    fun isDeviceCredentialEnrolled(): Boolean

    /**
     * Checks authentication status for [method].
     */
    fun checkAuthenticatorStatus(method: MarkAuthenticatorMethod): MarkAuthenticationStatus

    /**
     * Checks strong biometric authentication status.
     */
    fun checkSecureAuthentication(): MarkAuthenticationStatus

    /**
     * Returns true when [method] can currently authenticate.
     */
    fun canAuthenticate(method: MarkAuthenticatorMethod): Boolean

    /**
     * Prompts user using device credential authentication.
     */
    fun authenticateDeviceCredential(
        activity: FragmentActivity,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callback: WeakAuthenticationCallback,
    )

    /**
     * Prompts user using weak biometric authentication.
     */
    fun authenticateBiometric(
        activity: FragmentActivity,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callback: WeakAuthenticationCallback,
    )

    /**
     * Returns true when biometric enrollment changed since key creation.
     */
    fun isBiometricChanged(alias: String): Boolean

    /**
     * Performs secure biometric auth in encrypt mode using internally managed key/cipher.
     */
    fun secureAuthenticateBiometricEncrypt(
        activity: FragmentActivity,
        alias: String,
        title: String,
        subTitle: String?,
        invalidatedByBiometricEnrollment: Boolean = false,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callback: SecureAuthenticationEncryptCallback,
    )

    /**
     * Performs secure biometric auth in encrypt mode using custom [cipher] and [secretKey].
     */
    fun secureAuthenticateBiometricEncrypt(
        activity: FragmentActivity,
        title: String,
        cipher: Cipher,
        secretKey: SecretKey,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callback: SecureAuthenticationEncryptCallback,
    )

    /**
     * Performs secure biometric auth in decrypt mode using internally managed key/cipher.
     */
    fun secureAuthenticateBiometricDecrypt(
        activity: FragmentActivity,
        alias: String,
        encodedIVKey: String,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callback: SecureAuthenticationDecryptCallback,
    )

    /**
     * Performs secure biometric auth in decrypt mode using custom [cipher] and [secretKey].
     */
    fun secureAuthenticateBiometricDecrypt(
        activity: FragmentActivity,
        encodedIVKey: String,
        cipher: Cipher,
        secretKey: SecretKey,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callback: SecureAuthenticationDecryptCallback,
    )

    /**
     * Encrypts [plainText] with [cipher] and returns Base64 result.
     */
    fun encrypt(cipher: Cipher, plainText: String): String

    /**
     * Decrypts byte array using [cipher].
     */
    fun decrypt(cipher: Cipher, encryptedText: ByteArray): String

    /**
     * Decrypts Base64 text using [cipher].
     */
    fun decrypt(cipher: Cipher, encryptedText: String): String
}
