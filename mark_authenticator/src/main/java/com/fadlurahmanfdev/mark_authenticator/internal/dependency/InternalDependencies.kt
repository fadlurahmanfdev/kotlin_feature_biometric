package com.fadlurahmanfdev.mark_authenticator.internal.dependency

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricManager as AndroidXBiometricManager
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

internal interface Base64DataSource {
    fun encode(raw: ByteArray): String
    fun decode(encoded: String): ByteArray
}

internal class AndroidBase64DataSource : Base64DataSource {
    override fun encode(raw: ByteArray): String = Base64.encodeToString(raw, Base64.NO_WRAP)
    override fun decode(encoded: String): ByteArray = Base64.decode(encoded, Base64.NO_WRAP)
}

internal interface DeviceCapabilityDataSource {
    val sdkInt: Int
    fun hasSystemFeature(feature: String): Boolean
    fun isFingerprintHardwareDetected(): Boolean
    fun hasEnrolledFingerprints(): Boolean
    fun isDeviceSecure(): Boolean
    fun canAuthenticate(authenticator: Int): Int?
}

internal class AndroidDeviceCapabilityDataSource(
    private val context: Context,
) : DeviceCapabilityDataSource {
    private val keyguardManager: KeyguardManager? =
        context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager

    private val fingerprintManager: FingerprintManager? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            context.getSystemService(Context.FINGERPRINT_SERVICE) as? FingerprintManager
        } else {
            null
        }

    private val biometricManager: BiometricManager? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            context.getSystemService(Context.BIOMETRIC_SERVICE) as? BiometricManager
        } else {
            null
        }

    override val sdkInt: Int = Build.VERSION.SDK_INT

    override fun hasSystemFeature(feature: String): Boolean {
        return context.packageManager.hasSystemFeature(feature)
    }

    override fun isFingerprintHardwareDetected(): Boolean {
        return fingerprintManager?.isHardwareDetected == true
    }

    override fun hasEnrolledFingerprints(): Boolean {
        return fingerprintManager?.hasEnrolledFingerprints() == true
    }

    override fun isDeviceSecure(): Boolean {
        return keyguardManager?.isDeviceSecure == true
    }

    override fun canAuthenticate(authenticator: Int): Int? {
        return biometricManager?.canAuthenticate(authenticator)
    }
}

internal interface SecretKeyDataSource {
    fun getSecretKey(alias: String): SecretKey?
    fun generateSecretKey(alias: String, invalidatedByBiometricEnrollment: Boolean): SecretKey
    fun deleteSecretKey(alias: String)
}

internal class AndroidSecretKeyDataSource : SecretKeyDataSource {
    override fun getSecretKey(alias: String): SecretKey? {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore.getKey(alias, null) as SecretKey?
    }

    override fun generateSecretKey(alias: String, invalidatedByBiometricEnrollment: Boolean): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
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
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    override fun deleteSecretKey(alias: String) {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        keyStore.deleteEntry(alias)
    }
}

internal interface CipherDataSource {
    fun createCipher(): Cipher
}

internal class DefaultCipherDataSource : CipherDataSource {
    override fun createCipher(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")
}

internal data class PromptRequest(
    val activity: FragmentActivity,
    val callback: BiometricPrompt.AuthenticationCallback,
    val cryptoObject: BiometricPrompt.CryptoObject?,
    val confirmationRequired: Boolean,
    val authenticator: Int,
    val title: String,
    val subTitle: String?,
    val description: String,
    val negativeText: String,
)

internal interface PromptDataSource {
    fun authenticate(request: PromptRequest)
}

internal class AndroidPromptDataSource(
    private val context: Context,
) : PromptDataSource {
    override fun authenticate(request: PromptRequest) {
        val executor = ContextCompat.getMainExecutor(context)
        val promptBuilder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(request.title)
            .setDescription(request.description)
            .setAllowedAuthenticators(request.authenticator)
            .setConfirmationRequired(request.confirmationRequired)

        if (!request.subTitle.isNullOrBlank()) {
            promptBuilder.setSubtitle(request.subTitle)
        }

        if (request.authenticator != AndroidXBiometricManager.Authenticators.DEVICE_CREDENTIAL) {
            promptBuilder.setNegativeButtonText(request.negativeText)
        }

        val prompt = BiometricPrompt(request.activity, executor, request.callback)
        val promptInfo = promptBuilder.build()
        if (request.cryptoObject == null) {
            prompt.authenticate(promptInfo)
        } else {
            prompt.authenticate(promptInfo, request.cryptoObject)
        }
    }
}
