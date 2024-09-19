package co.id.fadlurahmanfdev.kotlin_feature_biometric.domain.plugin

import android.app.Activity
import android.content.DialogInterface.OnClickListener
import android.hardware.biometrics.BiometricManager.Authenticators
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import co.id.fadlurahmanfdev.kotlin_feature_biometric.data.callback.FeatureBiometricSecureCallBack
import co.id.fadlurahmanfdev.kotlin_feature_biometric.data.exception.FeatureBiometricException
import java.security.KeyStore
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class KotlinFeatureBiometric(private val activity: Activity) {
    companion object {
        @RequiresApi(Build.VERSION_CODES.M)
        private fun generateSecretKey(keyGenParameterSpec: KeyGenParameterSpec): SecretKey {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
            )
            keyGenerator.init(keyGenParameterSpec)
            return keyGenerator.generateKey()
        }

        private fun generateSecretKey(): SecretKey {
            val keyGenerator = KeyGenerator.getInstance("AES")
            keyGenerator.init(256)
            return keyGenerator.generateKey()
        }

        private fun getCipher(): Cipher {
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                Cipher.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES + "/"
                            + KeyProperties.BLOCK_MODE_CBC + "/"
                            + KeyProperties.ENCRYPTION_PADDING_PKCS7
                )
            } else {
                Cipher.getInstance("AES/CBC/PKCS7Padding")
            }
        }

        @RequiresApi(Build.VERSION_CODES.M)
        private fun generateKeyGenParameterSpec(alias: String): KeyGenParameterSpec {
            return KeyGenParameterSpec.Builder(
                alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            ).apply {
                setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                setUserAuthenticationRequired(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    setInvalidatedByBiometricEnrollment(true)
                }
            }.build()
        }

        private fun getSecretKey(alias: String): SecretKey {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            try {
                val existingSecretKey =
                    keyStore.getKey(alias, null) as SecretKey?
                if (existingSecretKey != null) {
                    return existingSecretKey
                }
            } catch (e: Exception) {
                throw FeatureBiometricException(code = "GET_EXISTING_KEY", message = e.message)
            }

            return when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.M -> {
                    val key = generateSecretKey(generateKeyGenParameterSpec(alias))
                    Log.d(
                        this::class.java.simpleName,
                        "successfully generate secret key with parameter spec $alias"
                    )
                    key
                }

                else -> {
                    val key = generateSecretKey()
                    Log.d(
                        this::class.java.simpleName,
                        "successfully generate secret key with $alias"
                    )
                    key
                }
            }
        }

        @RequiresApi(Build.VERSION_CODES.P)
        private fun getBiometricPromptP(
            activity: Activity,
            title: String,
            description: String,
            negativeText: String,
            executor: Executor,
            listener: OnClickListener,
        ): BiometricPrompt {
            return BiometricPrompt.Builder(activity).setTitle(title).setDescription(description)
                .apply {
                    setNegativeButton(negativeText, executor, listener)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG)
                    }
                }.build()
        }

        private fun getAndroidXPromptInfo(
            title: String,
            description: String,
            negativeText: String,
        ): androidx.biometric.BiometricPrompt.PromptInfo {
            return androidx.biometric.BiometricPrompt.PromptInfo.Builder().setTitle(title)
                .setDescription(description).setNegativeButtonText(negativeText)
                .build()
        }

        fun getAndroidXBiometricPrompt(
            fragmentActivity: FragmentActivity,
            executor: Executor,
            callBack: androidx.biometric.BiometricPrompt.AuthenticationCallback,
        ): androidx.biometric.BiometricPrompt {
            return androidx.biometric.BiometricPrompt(
                fragmentActivity,
                executor,
                callBack,
            )
        }
    }


    fun authenticateSecureEncrypt(
        alias: String,
        title: String,
        description: String,
        negativeText: String,
        cancellationSignal: CancellationSignal,
        callBack: FeatureBiometricSecureCallBack,
    ) {
        val executor = ContextCompat.getMainExecutor(activity)
        val cipher = getCipher()
        val secretKey = getSecretKey(alias)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P -> {
                val biometricPrompt = getBiometricPromptP(
                    activity = activity,
                    title = title,
                    description = description,
                    negativeText = negativeText,
                    executor = executor,
                    listener = { dialog, which -> callBack.onDialogClick(dialog, which) },
                )

                biometricPrompt.authenticate(
                    BiometricPrompt.CryptoObject(cipher),
                    cancellationSignal,
                    executor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
                            super.onAuthenticationSucceeded(result)
                            val currentCipher = result?.cryptoObject?.cipher
                            if (currentCipher == null) {
                                callBack.onErrorAuthenticate(
                                    exception = FeatureBiometricException(
                                        code = "CIPHER_MISSING_00",
                                        message = "Cipher missing"
                                    )
                                )
                                return
                            }

                            val encodedIvKey =
                                Base64.encodeToString(currentCipher.iv, Base64.NO_WRAP)

                            callBack.onSuccessAuthenticateEncryptSecureBiometric(
                                cipher = cipher,
                                encodedIvKey = encodedIvKey
                            )
                        }

                        override fun onAuthenticationFailed() {
                            super.onAuthenticationFailed()
                            callBack.onFailedAuthenticate()
                        }

                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence?
                        ) {
                            super.onAuthenticationError(errorCode, errString)
                            callBack.onErrorAuthenticate(
                                FeatureBiometricException(
                                    code = "$errorCode",
                                    message = errString?.toString()
                                )
                            )
                        }
                    },
                )
            }

            else -> {
                val promptInfo = getAndroidXPromptInfo(
                    title = title,
                    description = description,
                    negativeText = negativeText
                )

                val biometricPrompt = getAndroidXBiometricPrompt(
                    fragmentActivity = activity as FragmentActivity,
                    executor = executor,
                    callBack = object :
                        androidx.biometric.BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: androidx.biometric.BiometricPrompt.AuthenticationResult) {
                            super.onAuthenticationSucceeded(result)
                            val currentCipher = result.cryptoObject?.cipher

                            if (currentCipher == null) {
                                callBack.onErrorAuthenticate(
                                    exception = FeatureBiometricException(
                                        code = "CIPHER_MISSING_00",
                                        message = "Cipher missing"
                                    )
                                )
                                return
                            }

                            val encodedIvKey =
                                Base64.encodeToString(currentCipher.iv, Base64.NO_WRAP)

                            callBack.onSuccessAuthenticateEncryptSecureBiometric(
                                cipher = cipher,
                                encodedIvKey = encodedIvKey
                            )
                        }

                        override fun onAuthenticationFailed() {
                            super.onAuthenticationFailed()
                            callBack.onFailedAuthenticate()
                        }

                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence
                        ) {
                            super.onAuthenticationError(errorCode, errString)
                            callBack.onErrorAuthenticate(
                                FeatureBiometricException(
                                    code = "$errorCode",
                                    message = errString.toString()
                                )
                            )
                        }
                    }
                )
                biometricPrompt.authenticate(
                    promptInfo,
                    androidx.biometric.BiometricPrompt.CryptoObject(cipher)
                )
            }
        }
    }

    fun authenticateSecureDecrypt(
        alias: String,
        encodedIvKey: String,
        title: String,
        description: String,
        negativeText: String,
        cancellationSignal: CancellationSignal,
        callBack: FeatureBiometricSecureCallBack,
    ) {
        val executor = ContextCompat.getMainExecutor(activity)
        val cipher = getCipher()
        val secretKey = getSecretKey(alias)
        try {
            val ivKey = Base64.decode(encodedIvKey, Base64.NO_WRAP)
            val ivSpec = IvParameterSpec(ivKey)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
        } catch (e: Exception) {
            callBack.onErrorAuthenticate(
                FeatureBiometricException(
                    code = "INIT_CIPHER",
                    message = e.message,
                )
            )
            return
        }

        when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P -> {
                val biometricPrompt = getBiometricPromptP(
                    activity = activity,
                    title = title,
                    description = description,
                    negativeText = negativeText,
                    executor = executor,
                    listener = { dialog, which -> callBack.onDialogClick(dialog, which) },
                )

                biometricPrompt.authenticate(
                    BiometricPrompt.CryptoObject(cipher),
                    cancellationSignal,
                    executor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
                            super.onAuthenticationSucceeded(result)
                            val currentCipher = result?.cryptoObject?.cipher
                            if (currentCipher == null) {
                                callBack.onErrorAuthenticate(
                                    exception = FeatureBiometricException(
                                        code = "CIPHER_MISSING_00",
                                        message = "Cipher missing"
                                    )
                                )
                                return
                            }
                            callBack.onSuccessAuthenticateDecryptSecureBiometric(cipher = cipher)
                        }

                        override fun onAuthenticationFailed() {
                            super.onAuthenticationFailed()
                            callBack.onFailedAuthenticate()
                        }

                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence?
                        ) {
                            super.onAuthenticationError(errorCode, errString)
                            callBack.onErrorAuthenticate(
                                FeatureBiometricException(
                                    code = "$errorCode",
                                    message = errString?.toString()
                                )
                            )
                        }
                    },
                )
            }

            else -> {
                val promptInfo = getAndroidXPromptInfo(
                    title = title,
                    description = description,
                    negativeText = negativeText
                )

                val biometricPrompt = getAndroidXBiometricPrompt(
                    fragmentActivity = activity as FragmentActivity,
                    executor = executor,
                    callBack = object :
                        androidx.biometric.BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: androidx.biometric.BiometricPrompt.AuthenticationResult) {
                            super.onAuthenticationSucceeded(result)
                            val currentCipher = result.cryptoObject?.cipher

                            if (currentCipher == null) {
                                callBack.onErrorAuthenticate(
                                    exception = FeatureBiometricException(
                                        code = "CIPHER_MISSING_00",
                                        message = "Cipher missing"
                                    )
                                )
                                return
                            }

                            val encodedIvKey =
                                Base64.encodeToString(currentCipher.iv, Base64.NO_WRAP)

                            callBack.onSuccessAuthenticateEncryptSecureBiometric(
                                cipher = cipher,
                                encodedIvKey = encodedIvKey
                            )
                        }

                        override fun onAuthenticationFailed() {
                            super.onAuthenticationFailed()
                            callBack.onFailedAuthenticate()
                        }

                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence
                        ) {
                            super.onAuthenticationError(errorCode, errString)
                            callBack.onErrorAuthenticate(
                                FeatureBiometricException(
                                    code = "$errorCode",
                                    message = errString.toString()
                                )
                            )
                        }
                    }
                )
                biometricPrompt.authenticate(
                    promptInfo,
                    androidx.biometric.BiometricPrompt.CryptoObject(cipher)
                )
            }
        }
    }

    fun encrypt(cipher: Cipher, plainText: String): String {
        val byteEncryptedPassword = cipher.doFinal(plainText.toByteArray())
        return Base64.encodeToString(byteEncryptedPassword, Base64.NO_WRAP)
    }

    fun decrypt(cipher: Cipher, encryptedPassword: ByteArray): String {
        return String(cipher.doFinal(encryptedPassword))
    }

    fun decrypt(cipher: Cipher, encryptedPassword: String): String {
        val decodedPassword =
            Base64.decode(encryptedPassword, Base64.NO_WRAP)
        return String(cipher.doFinal(decodedPassword))
    }
}