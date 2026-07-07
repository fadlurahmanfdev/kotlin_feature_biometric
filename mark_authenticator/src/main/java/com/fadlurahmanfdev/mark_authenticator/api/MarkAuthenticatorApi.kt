package com.fadlurahmanfdev.mark_authenticator.api

import androidx.fragment.app.FragmentActivity
import com.fadlurahmanfdev.mark_authenticator.api.callback.SecureAuthenticationDecryptCallback
import com.fadlurahmanfdev.mark_authenticator.api.callback.SecureAuthenticationEncryptCallback
import com.fadlurahmanfdev.mark_authenticator.api.callback.WeakAuthenticationCallback
import com.fadlurahmanfdev.mark_authenticator.domain.enums.MarkAuthenticationStatus
import com.fadlurahmanfdev.mark_authenticator.domain.enums.MarkAuthenticatorMethod
import javax.crypto.Cipher
import javax.crypto.SecretKey

/**
 * Public contract exposed by Mark Authenticator.
 *
 * It groups capability checks, prompt-based authentication, and secure cryptography helpers.
 */
interface MarkAuthenticatorApi {
    /**
     * Generates a new secret key in Android KeyStore.
     *
     * @param alias unique key identifier.
     * @param invalidatedByBiometricEnrollment if `true`, biometric enrollment changes invalidate the key.
     */
    fun generateSecretKey(alias: String, invalidatedByBiometricEnrollment: Boolean = false): SecretKey

    /**
     * Deletes a secret key from Android KeyStore.
     *
     * This is a no-op when the key does not exist.
     */
    fun deleteSecretKey(alias: String)

    /**
     * Checks whether fingerprint hardware is available on the current device.
     */
    fun isDeviceSupportFingerprint(): Boolean

    /**
     * Checks whether face biometric hardware is available on the current device.
     */
    fun isDeviceSupportFaceAuth(): Boolean

    /**
     * Checks whether the device supports at least one biometric method.
     */
    fun isDeviceSupportBiometric(): Boolean

    /**
     * Checks whether at least one biometric credential is enrolled.
     */
    fun isBiometricEnrolled(): Boolean

    /**
     * Checks whether a device credential (PIN, pattern, or password) is enrolled.
     */
    fun isDeviceCredentialEnrolled(): Boolean

    /**
     * Returns normalized capability status for the provided authentication [method].
     */
    fun checkAuthenticatorStatus(method: MarkAuthenticatorMethod): MarkAuthenticationStatus

    /**
     * Returns normalized capability status for secure authentication (strong biometric).
     */
    fun checkSecureAuthentication(): MarkAuthenticationStatus

    /**
     * Returns `true` when [method] can authenticate right now.
     */
    fun canAuthenticate(method: MarkAuthenticatorMethod): Boolean

    /**
     * Shows authentication prompt using device credential authenticator.
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
     * Shows authentication prompt using weak biometric authenticator.
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
     * Detects whether biometric enrollment has changed for a key stored under [alias].
     *
     * @return `true` if key became permanently invalid due to biometric enrollment changes.
     */
    fun isBiometricChanged(alias: String): Boolean

    /**
     * Performs strong-biometric authentication for encryption with internally managed key/cipher.
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
     * Performs strong-biometric authentication for encryption using provided [cipher] and [secretKey].
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
     * Performs strong-biometric authentication for decryption with internally managed key/cipher.
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
     * Performs strong-biometric authentication for decryption using provided [cipher] and [secretKey].
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
     * Encrypts [plainText] with authenticated [cipher] and returns Base64 encoded result.
     */
    fun encrypt(cipher: Cipher, plainText: String): String

    /**
     * Decrypts [encryptedText] bytes with authenticated [cipher].
     */
    fun decrypt(cipher: Cipher, encryptedText: ByteArray): String

    /**
     * Decrypts Base64 [encryptedText] with authenticated [cipher].
     */
    fun decrypt(cipher: Cipher, encryptedText: String): String
}
