package com.fadlurahmanfdev.mark_authenticator.api

import android.content.Context
import androidx.fragment.app.FragmentActivity
import com.fadlurahmanfdev.mark_authenticator.api.callback.SecureAuthenticationDecryptCallback
import com.fadlurahmanfdev.mark_authenticator.api.callback.SecureAuthenticationEncryptCallback
import com.fadlurahmanfdev.mark_authenticator.api.callback.WeakAuthenticationCallback
import com.fadlurahmanfdev.mark_authenticator.internal.MarkAuthenticatorInternal
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.AndroidBase64DataSource
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.AndroidDeviceCapabilityDataSource
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.AndroidPromptDataSource
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.AndroidSecretKeyDataSource
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.DefaultCipherDataSource
import com.fadlurahmanfdev.mark_authenticator.core.enums.MarkAuthenticationStatus
import com.fadlurahmanfdev.mark_authenticator.core.enums.MarkAuthenticatorMethod
import javax.crypto.Cipher
import javax.crypto.SecretKey

/**
 * Public entry point for Mark Authenticator.
 *
 * This class delegates every call to an internal implementation that is split by layer:
 * `api` (contracts), `model` (public models), `core` (shared constants), and `internal`
 * (Android-specific implementation).
 */
class MarkAuthenticator(context: Context) {
    private val internal = MarkAuthenticatorInternal(
        capabilityDataSource = AndroidDeviceCapabilityDataSource(context),
        secretKeyDataSource = AndroidSecretKeyDataSource(),
        cipherDataSource = DefaultCipherDataSource(),
        promptDataSource = AndroidPromptDataSource(context),
        base64DataSource = AndroidBase64DataSource(),
    )

    fun cipher(): Cipher = internal.cipher()

    fun getSecretKey(alias: String): SecretKey? = internal.getSecretKey(alias)

    fun generateSecretKey(alias: String, invalidatedByBiometricEnrollment: Boolean): SecretKey =
        internal.generateSecretKey(
            alias = alias,
            invalidatedByBiometricEnrollment = invalidatedByBiometricEnrollment
        )

    fun deleteSecretKey(alias: String) = internal.deleteSecretKey(alias = alias)

    fun isDeviceSupportFingerprint(): Boolean = internal.isDeviceSupportFingerprint()

    fun isDeviceSupportFaceAuth(): Boolean = internal.isDeviceSupportFaceAuth()

    fun isDeviceSupportBiometric(): Boolean = internal.isDeviceSupportBiometric()

    fun isBiometricEnrolled(): Boolean = internal.isBiometricEnrolled()

    fun isDeviceCredentialEnrolled(): Boolean = internal.isDeviceCredentialEnrolled()

    fun checkAuthenticatorStatus(method: MarkAuthenticatorMethod): MarkAuthenticationStatus =
        internal.checkAuthenticatorStatus(method = method)

    fun checkSecureAuthentication(): MarkAuthenticationStatus = internal.checkSecureAuthentication()

    fun canAuthenticate(method: MarkAuthenticatorMethod): Boolean =
        internal.canAuthenticate(method = method)

    fun authenticateDeviceCredential(
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
        callback = callback
    )

    fun authenticateBiometric(
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
        callback = callback
    )

    fun isBiometricChanged(alias: String): Boolean = internal.isBiometricChanged(alias = alias)

    fun secureAuthenticateBiometricEncrypt(
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
    ) = internal.secureAuthenticateBiometricEncrypt(
        activity = activity,
        title = title,
        cipher = cipher,
        secretKey = secretKey,
        subTitle = subTitle,
        description = description,
        negativeText = negativeText,
        confirmationRequired = confirmationRequired,
        callback = callback
    )

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
    ) = internal.secureAuthenticateBiometricDecrypt(
        activity = activity,
        alias = alias,
        encodedIVKey = encodedIVKey,
        title = title,
        subTitle = subTitle,
        description = description,
        negativeText = negativeText,
        confirmationRequired = confirmationRequired,
        callback = callback
    )

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
        callback = callback
    )

    fun encrypt(cipher: Cipher, plainText: String): String =
        internal.encrypt(cipher = cipher, plainText = plainText)

    fun decrypt(cipher: Cipher, encryptedText: ByteArray): String = internal.decrypt(
        cipher = cipher,
        encryptedText = encryptedText,
    )

    fun decrypt(cipher: Cipher, encryptedText: String): String = internal.decrypt(
        cipher = cipher,
        encryptedText = encryptedText
    )
}