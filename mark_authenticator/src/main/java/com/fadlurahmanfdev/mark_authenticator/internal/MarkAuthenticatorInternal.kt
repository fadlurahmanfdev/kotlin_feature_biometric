package com.fadlurahmanfdev.mark_authenticator.internal

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricManager as AndroidXBiometricManager
import com.fadlurahmanfdev.mark_authenticator.api.MarkAuthenticatorApi
import com.fadlurahmanfdev.mark_authenticator.api.callback.SecureAuthenticationDecryptCallback
import com.fadlurahmanfdev.mark_authenticator.api.callback.SecureAuthenticationEncryptCallback
import com.fadlurahmanfdev.mark_authenticator.api.callback.WeakAuthenticationCallback
import com.fadlurahmanfdev.mark_authenticator.core.constant.ErrorConstant
import com.fadlurahmanfdev.mark_authenticator.internal.model.MarkAuthenticationType
import com.fadlurahmanfdev.mark_authenticator.model.MarkAuthenticationStatus
import com.fadlurahmanfdev.mark_authenticator.model.MarkAuthenticatorException
import com.fadlurahmanfdev.mark_authenticator.model.MarkAuthenticatorMethod
import java.nio.charset.StandardCharsets
import java.security.InvalidKeyException
import java.security.KeyStore
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal class MarkAuthenticatorInternal(private val context: Context) : MarkAuthenticatorApi {
    private val keyguardManager: KeyguardManager =
        context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager

    private val fingerprintManager: FingerprintManager? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            context.getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager
        } else {
            null
        }

    private val biometricManager: BiometricManager? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            context.getSystemService(Context.BIOMETRIC_SERVICE) as BiometricManager
        } else {
            null
        }

    override fun cipher(): Cipher {
        return Cipher.getInstance("AES/GCM/NoPadding")
    }

    override fun getSecretKey(alias: String): SecretKey? {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return try {
            keyStore.getKey(alias, null) as SecretKey?
        } catch (e: Throwable) {
            throw MarkAuthenticatorException(
                code = ErrorConstant.UNABLE_FETCH_GET_SECRET_KEY,
                message = e.message,
                cause = e,
            )
        }
    }

    override fun generateSecretKey(alias: String, invalidatedByBiometricEnrollment: Boolean): SecretKey {
        if (getSecretKey(alias) != null) {
            throw MarkAuthenticatorException(
                code = ErrorConstant.SECRET_KEY_ALREADY_EXIST,
                message = "Secret key already exists for alias: $alias",
            )
        }

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        keyGenerator.init(
            generateKeyGenParameterSpec(
                alias = alias,
                invalidatedByBiometricEnrollment = invalidatedByBiometricEnrollment,
            ),
        )
        return keyGenerator.generateKey()
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun generateKeyGenParameterSpec(
        alias: String,
        invalidatedByBiometricEnrollment: Boolean,
    ): KeyGenParameterSpec {
        return KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        ).apply {
            setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment)
            }
        }.build()
    }

    override fun deleteSecretKey(alias: String) {
        if (getSecretKey(alias) == null) return

        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        try {
            keyStore.deleteEntry(alias)
        } catch (e: Throwable) {
            throw MarkAuthenticatorException(
                code = ErrorConstant.UNABLE_TO_DELETE_SECRET_KEY,
                message = e.message,
                cause = e,
            )
        }
    }

    override fun isDeviceSupportFingerprint(): Boolean {
        return when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q ->
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)

            Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ->
                fingerprintManager?.isHardwareDetected == true

            else -> false
        }
    }

    override fun isDeviceSupportFaceAuth(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_FACE) ||
                context.packageManager.hasSystemFeature("com.samsung.android.bio.face")
        } else {
            context.packageManager.hasSystemFeature("com.samsung.android.bio.face")
        }
    }

    override fun isDeviceSupportBiometric(): Boolean {
        return isDeviceSupportFingerprint() || isDeviceSupportFaceAuth()
    }

    override fun isBiometricEnrolled(): Boolean {
        return checkAuthenticatorStatus(MarkAuthenticatorMethod.BIOMETRIC) == MarkAuthenticationStatus.SUCCESS
    }

    override fun isDeviceCredentialEnrolled(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            keyguardManager.isDeviceSecure
        } else {
            false
        }
    }

    private fun checkAuthenticatorStatusByType(type: MarkAuthenticationType): MarkAuthenticationStatus {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val androidAuthenticator = when (type) {
                MarkAuthenticationType.BIOMETRIC_WEAK ->
                    BiometricManager.Authenticators.BIOMETRIC_WEAK

                MarkAuthenticationType.BIOMETRIC_STRONG ->
                    BiometricManager.Authenticators.BIOMETRIC_STRONG

                MarkAuthenticationType.DEVICE_CREDENTIAL ->
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL
            }

            val status = biometricManager?.canAuthenticate(androidAuthenticator)
                ?: return MarkAuthenticationStatus.UNKNOWN

            return when (status) {
                BiometricManager.BIOMETRIC_SUCCESS -> MarkAuthenticationStatus.SUCCESS
                BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> MarkAuthenticationStatus.NO_HARDWARE
                BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> MarkAuthenticationStatus.UNAVAILABLE
                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> MarkAuthenticationStatus.NONE_ENROLLED
                BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED ->
                    MarkAuthenticationStatus.SECURITY_UPDATE_REQUIRED

                else -> MarkAuthenticationStatus.UNKNOWN
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return when (type) {
                MarkAuthenticationType.BIOMETRIC_WEAK ->
                    when {
                        !isDeviceSupportBiometric() -> MarkAuthenticationStatus.NO_HARDWARE
                        fingerprintManager?.hasEnrolledFingerprints() == true -> MarkAuthenticationStatus.SUCCESS
                        else -> MarkAuthenticationStatus.NONE_ENROLLED
                    }

                MarkAuthenticationType.BIOMETRIC_STRONG ->
                    when {
                        !isDeviceSupportBiometric() -> MarkAuthenticationStatus.NO_HARDWARE
                        fingerprintManager?.hasEnrolledFingerprints() == true -> MarkAuthenticationStatus.SUCCESS
                        else -> MarkAuthenticationStatus.NONE_ENROLLED
                    }

                MarkAuthenticationType.DEVICE_CREDENTIAL ->
                    if (keyguardManager.isDeviceSecure) {
                        MarkAuthenticationStatus.SUCCESS
                    } else {
                        MarkAuthenticationStatus.NONE_ENROLLED
                    }
            }
        }

        return MarkAuthenticationStatus.UNSUPPORTED_OS_VERSION
    }

    override fun checkAuthenticatorStatus(method: MarkAuthenticatorMethod): MarkAuthenticationStatus {
        return when (method) {
            MarkAuthenticatorMethod.BIOMETRIC ->
                checkAuthenticatorStatusByType(MarkAuthenticationType.BIOMETRIC_WEAK)

            MarkAuthenticatorMethod.DEVICE_CREDENTIAL ->
                checkAuthenticatorStatusByType(MarkAuthenticationType.DEVICE_CREDENTIAL)
        }
    }

    override fun checkSecureAuthentication(): MarkAuthenticationStatus {
        return checkAuthenticatorStatusByType(MarkAuthenticationType.BIOMETRIC_STRONG)
    }

    override fun canAuthenticate(method: MarkAuthenticatorMethod): Boolean {
        return checkAuthenticatorStatus(method) == MarkAuthenticationStatus.SUCCESS
    }

    override fun authenticateDeviceCredential(
        activity: FragmentActivity,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callback: WeakAuthenticationCallback,
    ) {
        authenticateWithPrompt(
            activity = activity,
            title = title,
            subTitle = subTitle,
            description = description,
            negativeText = negativeText,
            confirmationRequired = confirmationRequired,
            authenticator = AndroidXBiometricManager.Authenticators.DEVICE_CREDENTIAL,
            cryptoObject = null,
            callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    callback.onSuccessAuthenticate()
                }

                override fun onAuthenticationFailed() {
                    callback.onFailedAuthenticate()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    dispatchAuthenticationError(errorCode, errString, callback)
                }
            },
        )
    }

    override fun authenticateBiometric(
        activity: FragmentActivity,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callback: WeakAuthenticationCallback,
    ) {
        authenticateWithPrompt(
            activity = activity,
            title = title,
            subTitle = subTitle,
            description = description,
            negativeText = negativeText,
            confirmationRequired = confirmationRequired,
            authenticator = AndroidXBiometricManager.Authenticators.BIOMETRIC_WEAK,
            cryptoObject = null,
            callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    callback.onSuccessAuthenticate()
                }

                override fun onAuthenticationFailed() {
                    callback.onFailedAuthenticate()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    dispatchAuthenticationError(errorCode, errString, callback)
                }
            },
        )
    }

    override fun isBiometricChanged(alias: String): Boolean {
        return try {
            val secretKey = getSecretKey(alias) ?: return false
            val encryptCipher = cipher()
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey)
            false
        } catch (e: KeyPermanentlyInvalidatedException) {
            true
        } catch (e: InvalidKeyException) {
            false
        } catch (e: Throwable) {
            throw MarkAuthenticatorException(
                code = ErrorConstant.UNABLE_TO_DETECT_BIOMETRIC_CHANGE,
                message = e.message,
                cause = e,
            )
        }
    }

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
    ) {
        val secretKey = getSecretKey(alias)
            ?: generateSecretKey(alias, invalidatedByBiometricEnrollment)
        secureAuthenticateBiometricEncrypt(
            activity = activity,
            title = title,
            cipher = cipher(),
            secretKey = secretKey,
            subTitle = subTitle,
            description = description,
            negativeText = negativeText,
            confirmationRequired = confirmationRequired,
            callback = callback,
        )
    }

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
    ) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            authenticateWithPrompt(
                activity = activity,
                title = title,
                subTitle = subTitle,
                description = description,
                negativeText = negativeText,
                confirmationRequired = confirmationRequired,
                authenticator = AndroidXBiometricManager.Authenticators.BIOMETRIC_STRONG,
                cryptoObject = BiometricPrompt.CryptoObject(cipher),
                callback = object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val cipherResult = result.cryptoObject?.cipher
                        if (cipherResult == null) {
                            callback.onErrorAuthenticate(
                                MarkAuthenticatorException(
                                    code = ErrorConstant.CIPHER_MISSING,
                                    message = "Cipher missing in authentication result",
                                ),
                            )
                            return
                        }

                        val encodedIv = Base64.encodeToString(cipherResult.iv, Base64.NO_WRAP)
                        callback.onSuccessAuthenticate(cipherResult, encodedIv)
                    }

                    override fun onAuthenticationFailed() {
                        callback.onFailedAuthenticate()
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        dispatchAuthenticationError(errorCode, errString, callback)
                    }
                },
            )
        } catch (e: KeyPermanentlyInvalidatedException) {
            callback.onErrorAuthenticate(
                MarkAuthenticatorException(
                    code = ErrorConstant.KEY_PERMANENTLY_INVALIDATED,
                    message = e.message,
                    cause = e,
                ),
            )
        } catch (e: Throwable) {
            callback.onErrorAuthenticate(
                MarkAuthenticatorException(
                    code = ErrorConstant.UNABLE_SECURE_AUTHENTICATE,
                    message = e.message,
                    cause = e,
                ),
            )
        }
    }

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
    ) {
        val secretKey = getSecretKey(alias) ?: throw MarkAuthenticatorException(
            code = ErrorConstant.SECRET_KEY_MISSING,
            message = "Secret key not found for alias: $alias",
        )
        secureAuthenticateBiometricDecrypt(
            activity = activity,
            encodedIVKey = encodedIVKey,
            cipher = cipher(),
            secretKey = secretKey,
            title = title,
            subTitle = subTitle,
            description = description,
            negativeText = negativeText,
            confirmationRequired = confirmationRequired,
            callback = callback,
        )
    }

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
    ) {
        try {
            val iv = Base64.decode(encodedIVKey, Base64.NO_WRAP)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
            authenticateWithPrompt(
                activity = activity,
                title = title,
                subTitle = subTitle,
                description = description,
                negativeText = negativeText,
                confirmationRequired = confirmationRequired,
                authenticator = AndroidXBiometricManager.Authenticators.BIOMETRIC_STRONG,
                cryptoObject = BiometricPrompt.CryptoObject(cipher),
                callback = object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val cipherResult = result.cryptoObject?.cipher
                        if (cipherResult == null) {
                            callback.onErrorAuthenticate(
                                MarkAuthenticatorException(
                                    code = ErrorConstant.CIPHER_MISSING,
                                    message = "Cipher missing in authentication result",
                                ),
                            )
                            return
                        }
                        callback.onSuccessAuthenticate(cipherResult)
                    }

                    override fun onAuthenticationFailed() {
                        callback.onFailedAuthenticate()
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        dispatchAuthenticationError(errorCode, errString, callback)
                    }
                },
            )
        } catch (e: KeyPermanentlyInvalidatedException) {
            callback.onErrorAuthenticate(
                MarkAuthenticatorException(
                    code = ErrorConstant.KEY_PERMANENTLY_INVALIDATED,
                    message = e.message,
                    cause = e,
                ),
            )
        } catch (e: Throwable) {
            callback.onErrorAuthenticate(
                MarkAuthenticatorException(
                    code = ErrorConstant.UNABLE_SECURE_AUTHENTICATE,
                    message = e.message,
                    cause = e,
                ),
            )
        }
    }

    private fun dispatchAuthenticationError(
        errorCode: Int,
        errString: CharSequence,
        callback: com.fadlurahmanfdev.mark_authenticator.api.callback.MarkAuthenticationCallback,
    ) {
        if (errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
            errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
            errorCode == BiometricPrompt.ERROR_CANCELED
        ) {
            callback.onCanceled()
            return
        }

        callback.onErrorAuthenticate(
            MarkAuthenticatorException(
                code = errorCode.toString(),
                message = errString.toString(),
            ),
        )
    }

    private fun authenticateWithPrompt(
        activity: FragmentActivity,
        callback: BiometricPrompt.AuthenticationCallback,
        cryptoObject: BiometricPrompt.CryptoObject?,
        confirmationRequired: Boolean,
        authenticator: Int,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
    ) {
        val executor = ContextCompat.getMainExecutor(context)
        val promptBuilder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setDescription(description)
            .setAllowedAuthenticators(authenticator)
            .setConfirmationRequired(confirmationRequired)

        if (!subTitle.isNullOrBlank()) {
            promptBuilder.setSubtitle(subTitle)
        }

        // Device credential prompt must not set negative button text.
        if (authenticator != AndroidXBiometricManager.Authenticators.DEVICE_CREDENTIAL) {
            promptBuilder.setNegativeButtonText(negativeText)
        }

        val prompt = BiometricPrompt(activity, executor, callback)
        val promptInfo = promptBuilder.build()
        if (cryptoObject == null) {
            prompt.authenticate(promptInfo)
        } else {
            prompt.authenticate(promptInfo, cryptoObject)
        }
    }

    override fun encrypt(cipher: Cipher, plainText: String): String {
        return Base64.encodeToString(
            cipher.doFinal(plainText.toByteArray(StandardCharsets.UTF_8)),
            Base64.NO_WRAP,
        )
    }

    override fun decrypt(cipher: Cipher, encryptedText: ByteArray): String {
        return try {
            String(cipher.doFinal(encryptedText), StandardCharsets.UTF_8)
        } catch (e: BadPaddingException) {
            throw MarkAuthenticatorException(
                code = ErrorConstant.BAD_PADDING,
                message = e.message,
                cause = e,
            )
        }
    }

    override fun decrypt(cipher: Cipher, encryptedText: String): String {
        return decrypt(cipher, Base64.decode(encryptedText, Base64.NO_WRAP))
    }
}
