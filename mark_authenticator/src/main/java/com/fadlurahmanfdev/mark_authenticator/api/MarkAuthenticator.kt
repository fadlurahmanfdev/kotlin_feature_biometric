package com.fadlurahmanfdev.mark_authenticator.api

import android.content.Context
import androidx.fragment.app.FragmentActivity
import com.fadlurahmanfdev.mark_authenticator.api.callback.SecureAuthenticationDecryptCallback
import com.fadlurahmanfdev.mark_authenticator.api.callback.SecureAuthenticationEncryptCallback
import com.fadlurahmanfdev.mark_authenticator.api.callback.WeakAuthenticationCallback
import com.fadlurahmanfdev.mark_authenticator.core.enums.MarkAuthenticationStatus
import com.fadlurahmanfdev.mark_authenticator.core.enums.MarkAuthenticatorMethod
import com.fadlurahmanfdev.mark_authenticator.internal.MarkAuthenticatorInternal
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.AndroidBase64DataSource
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.AndroidDeviceCapabilityDataSource
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.AndroidPromptDataSource
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.AndroidSecretKeyDataSource
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.DefaultCipherDataSource
import javax.crypto.Cipher
import javax.crypto.SecretKey

/**
 * Public entry point for Mark Authenticator.
 *
 * This class delegates all operations to the internal implementation while keeping a stable,
 * consumer-friendly API.
 */
class MarkAuthenticator(context: Context) : MarkAuthenticatorApi {
    private val internal = MarkAuthenticatorInternal(
        capabilityDataSource = AndroidDeviceCapabilityDataSource(context),
        secretKeyDataSource = AndroidSecretKeyDataSource(),
        cipherDataSource = DefaultCipherDataSource(),
        promptDataSource = AndroidPromptDataSource(context),
        base64DataSource = AndroidBase64DataSource(),
    )

    /**
     * Creates a new AES/GCM cipher instance used by secure authentication flows.
     */
    override fun cipher(): Cipher = internal.cipher()

    /**
     * Gets secret key from Android KeyStore by [alias].
     *
     * @return existing key, or `null` when key is not found.
     */
    override fun getSecretKey(alias: String): SecretKey? = internal.getSecretKey(alias)

    /**
     * Generates a new Android KeyStore secret key for [alias].
     *
     * @param invalidatedByBiometricEnrollment if `true`, biometric enrollment changes invalidate key.
     */
    override fun generateSecretKey(
        alias: String,
        invalidatedByBiometricEnrollment: Boolean,
    ): SecretKey = internal.generateSecretKey(
        alias = alias,
        invalidatedByBiometricEnrollment = invalidatedByBiometricEnrollment,
    )

    /**
     * Deletes key stored under [alias]. This is a no-op when key does not exist.
     */
    override fun deleteSecretKey(alias: String) = internal.deleteSecretKey(alias = alias)

    /**
     * Checks whether fingerprint hardware is available.
     */
    override fun isDeviceSupportFingerprint(): Boolean = internal.isDeviceSupportFingerprint()

    /**
     * Checks whether face-authentication hardware is available.
     */
    override fun isDeviceSupportFaceAuth(): Boolean = internal.isDeviceSupportFaceAuth()

    /**
     * Checks whether at least one biometric method is supported.
     */
    override fun isDeviceSupportBiometric(): Boolean = internal.isDeviceSupportBiometric()

    /**
     * Checks whether biometric credential is already enrolled.
     */
    override fun isBiometricEnrolled(): Boolean = internal.isBiometricEnrolled()

    /**
     * Checks whether PIN/pattern/password is already enrolled.
     */
    override fun isDeviceCredentialEnrolled(): Boolean = internal.isDeviceCredentialEnrolled()

    /**
     * Returns normalized status for [method].
     */
    override fun checkAuthenticatorStatus(method: MarkAuthenticatorMethod): MarkAuthenticationStatus =
        internal.checkAuthenticatorStatus(method = method)

    /**
     * Returns normalized status for secure authentication (strong biometric).
     */
    override fun checkSecureAuthentication(): MarkAuthenticationStatus = internal.checkSecureAuthentication()

    /**
     * Returns `true` when [method] can authenticate in current device state.
     */
    override fun canAuthenticate(method: MarkAuthenticatorMethod): Boolean =
        internal.canAuthenticate(method = method)

    /**
     * Shows device credential authentication prompt.
     */
    override fun authenticateDeviceCredential(
        activity: FragmentActivity,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callback: WeakAuthenticationCallback,
    ) = internal.authenticateDeviceCredential(
        activity = activity,
        title = title,
        subTitle = subTitle,
        description = description,
        negativeText = negativeText,
        confirmationRequired = confirmationRequired,
        callback = callback,
    )

    /**
     * Shows weak biometric authentication prompt.
     */
    override fun authenticateBiometric(
        activity: FragmentActivity,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callback: WeakAuthenticationCallback,
    ) = internal.authenticateBiometric(
        activity = activity,
        title = title,
        subTitle = subTitle,
        description = description,
        negativeText = negativeText,
        confirmationRequired = confirmationRequired,
        callback = callback,
    )

    /**
     * Detects whether biometric enrollment changed after key creation for [alias].
     */
    override fun isBiometricChanged(alias: String): Boolean = internal.isBiometricChanged(alias = alias)

    /**
     * Authenticates using strong biometric and prepares cipher for encryption.
     *
     * This overload manages key and cipher internally.
     */
    override fun secureAuthenticateBiometricEncrypt(
        activity: FragmentActivity,
        alias: String,
        title: String,
        subTitle: String?,
        invalidatedByBiometricEnrollment: Boolean,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callback: SecureAuthenticationEncryptCallback,
    ) = internal.secureAuthenticateBiometricEncrypt(
        activity = activity,
        alias = alias,
        title = title,
        subTitle = subTitle,
        invalidatedByBiometricEnrollment = invalidatedByBiometricEnrollment,
        description = description,
        negativeText = negativeText,
        confirmationRequired = confirmationRequired,
        callback = callback,
    )

    /**
     * Authenticates using strong biometric and prepares provided [cipher]/[secretKey] for encryption.
     */
    override fun secureAuthenticateBiometricEncrypt(
        activity: FragmentActivity,
        title: String,
        cipher: Cipher,
        secretKey: SecretKey,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callback: SecureAuthenticationEncryptCallback,
    ) = internal.secureAuthenticateBiometricEncrypt(
        activity = activity,
        title = title,
        cipher = cipher,
        secretKey = secretKey,
        subTitle = subTitle,
        description = description,
        negativeText = negativeText,
        confirmationRequired = confirmationRequired,
        callback = callback,
    )

    /**
     * Authenticates using strong biometric and prepares cipher for decryption.
     *
     * This overload manages key and cipher internally.
     */
    override fun secureAuthenticateBiometricDecrypt(
        activity: FragmentActivity,
        alias: String,
        encodedIVKey: String,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callback: SecureAuthenticationDecryptCallback,
    ) = internal.secureAuthenticateBiometricDecrypt(
        activity = activity,
        alias = alias,
        encodedIVKey = encodedIVKey,
        title = title,
        subTitle = subTitle,
        description = description,
        negativeText = negativeText,
        confirmationRequired = confirmationRequired,
        callback = callback,
    )

    /**
     * Authenticates using strong biometric and prepares provided [cipher]/[secretKey] for decryption.
     */
    override fun secureAuthenticateBiometricDecrypt(
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
    ) = internal.secureAuthenticateBiometricDecrypt(
        activity = activity,
        encodedIVKey = encodedIVKey,
        cipher = cipher,
        secretKey = secretKey,
        title = title,
        subTitle = subTitle,
        description = description,
        negativeText = negativeText,
        confirmationRequired = confirmationRequired,
        callback = callback,
    )

    /**
     * Encrypts plaintext using authenticated [cipher], then returns Base64 encoded text.
     */
    override fun encrypt(cipher: Cipher, plainText: String): String =
        internal.encrypt(cipher = cipher, plainText = plainText)

    /**
     * Decrypts raw encrypted bytes using authenticated [cipher].
     */
    override fun decrypt(cipher: Cipher, encryptedText: ByteArray): String = internal.decrypt(
        cipher = cipher,
        encryptedText = encryptedText,
    )

    /**
     * Decrypts Base64 encoded text using authenticated [cipher].
     */
    override fun decrypt(cipher: Cipher, encryptedText: String): String = internal.decrypt(
        cipher = cipher,
        encryptedText = encryptedText,
    )
}
