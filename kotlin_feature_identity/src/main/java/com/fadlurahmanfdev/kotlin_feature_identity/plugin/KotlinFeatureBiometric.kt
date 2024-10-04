package com.fadlurahmanfdev.kotlin_feature_identity.plugin

import android.app.Activity
import android.content.DialogInterface.OnClickListener
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager.Authenticators
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.FeatureBiometricCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.FeatureBiometricDecryptSecureCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.FeatureBiometricEncryptSecureCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.BiometricType
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureBiometricStatus
import com.fadlurahmanfdev.kotlin_feature_identity.data.exception.FeatureBiometricException
import java.security.KeyStore
import java.util.concurrent.Executor
import javax.crypto.BadPaddingException
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

        private fun deleteSecretKey(alias: String) {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            try {
                keyStore.deleteEntry(alias)
            } catch (e: Exception) {
                Log.e(
                    KotlinFeatureBiometric::class.java.simpleName,
                    "failed to delete secret key: $alias"
                )
                throw FeatureBiometricException(code = "GET_EXISTING_KEY", message = e.message)
            }
        }

        @RequiresApi(Build.VERSION_CODES.P)
        private fun getBiometricPromptP(
            activity: Activity,
            type: BiometricType,
            title: String,
            description: String,
            negativeText: String,
            executor: Executor,
            listener: OnClickListener,
        ): BiometricPrompt {
            return BiometricPrompt.Builder(activity).setTitle(title).setDescription(description)
                .apply {
                    when (type) {
                        BiometricType.WEAK -> {
                            setNegativeButton(negativeText, executor, listener)
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                setAllowedAuthenticators(Authenticators.BIOMETRIC_WEAK)
                            }
                        }

                        BiometricType.STRONG -> {
                            setNegativeButton(negativeText, executor, listener)
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG)
                            }
                        }

                        BiometricType.DEVICE_CREDENTIAL -> {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                setAllowedAuthenticators(Authenticators.DEVICE_CREDENTIAL)
                            }
                        }
                    }
                }.build()
        }

        private fun getAndroidXPromptInfo(
            title: String,
            type: BiometricType,
            description: String,
            negativeText: String,
        ): androidx.biometric.BiometricPrompt.PromptInfo {
            return androidx.biometric.BiometricPrompt.PromptInfo.Builder().setTitle(title)
                .setDescription(description).setNegativeButtonText(negativeText)
                .apply {
                    when (type) {
                        BiometricType.WEAK -> {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_WEAK)
                            }
                        }

                        BiometricType.STRONG -> {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                            }
                        }

                        BiometricType.DEVICE_CREDENTIAL -> {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                setAllowedAuthenticators(BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                            }
                        }
                    }
                }
                .build()
        }

        private fun getAndroidXBiometricPrompt(
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

    /**
     * Determines the device's have feature biometric
     *
     * @return The boolean indicate which the device have feature biometric
     */
    fun haveFeatureBiometric(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            activity.packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT) || activity.packageManager.hasSystemFeature(
                PackageManager.FEATURE_FACE
            )
        } else {
            false
        }
    }

    /**
     * Determines the device's have feature biometric
     *
     * @return The boolean indicate which the device have feature biometric
     */
    fun haveFaceDetection(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            activity.packageManager.hasSystemFeature(PackageManager.FEATURE_FACE) or activity.packageManager.hasSystemFeature(
                "com.samsung.android.bio.face"
            )
        } else {
            false
        }
    }

    /**
     * Determines the device's can authenticate using biometric
     *
     * @return The boolean indicate which the device can authenticate using biometric
     */
    fun canAuthenticate(authenticators: Int = androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK or androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL): Boolean {
        return checkBiometricStatus(authenticators) == FeatureBiometricStatus.SUCCESS
    }

    /**
     * Determines the device's ability to authenticate using biometrics or device credentials.
     *
     * This function uses the `BiometricManager` to check the current biometric and device credential
     * authentication capabilities and returns a corresponding `CanAuthenticateReasonType` value.
     *
     * It checks for the following authentication states:
     *
     * - `CanAuthenticateReasonType.SUCCESS`: Biometric authentication is available and the user is enrolled.
     * - `CanAuthenticateReasonType.NO_BIOMETRIC_AVAILABLE`: No biometric hardware is available on the device.
     * - `CanAuthenticateReasonType.BIOMETRIC_UNAVAILABLE`: Biometric hardware is temporarily unavailable (e.g., being used by another process).
     * - `CanAuthenticateReasonType.NONE_ENROLLED`: Biometric hardware is available, but the user has not enrolled any biometric credentials.
     * - `CanAuthenticateReasonType.UNKNOWN`: An unknown error occurred during the authentication capability check.
     *
     * If the function returns `CanAuthenticateReasonType.NONE_ENROLLED`, you can guide the user to enroll their biometrics
     * by starting the biometric enrollment intent with:
     *
     * ```kotlin
     * val enrollIntent = Intent(Settings.ACTION_BIOMETRIC_ENROLL).apply {
     *     putExtra(Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
     *         BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
     * }
     * startActivityForResult(enrollIntent, REQUEST_CODE)
     * ```
     *
     * @return The reason type indicating the result of the biometric or device credential authentication check.
     */
    fun checkBiometricStatus(authenticators: Int): FeatureBiometricStatus {
        val biometricManager = androidx.biometric.BiometricManager.from(activity)
        return when (biometricManager.canAuthenticate(authenticators)) {
            androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS ->
                FeatureBiometricStatus.SUCCESS

            androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE ->
                FeatureBiometricStatus.NO_BIOMETRIC_AVAILABLE

            androidx.biometric.BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
                FeatureBiometricStatus.BIOMETRIC_UNAVAILABLE

            androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                FeatureBiometricStatus.NONE_ENROLLED
            }

            else -> {
                FeatureBiometricStatus.UNKNOWN
            }
        }
    }

    /**
     * Initiates a secure biometric authentication process for encryption using the provided alias and cipher.
     *
     * This function sets up and prompts the user for biometric authentication (or device credentials, depending on the device’s support).
     * If authentication succeeds, the provided cipher will be initialized for encryption, and an initialization vector (IV) will be
     * generated and returned in base64 format. The IV is necessary for decryption of the encrypted data.
     *
     * The function adapts the authentication mechanism based on the device's Android version:
     *
     * - **Android P (API 28) and above**: Uses the updated `BiometricPrompt` API for stronger biometric security.
     * - **Android below P**: Uses the older `androidx.biometric.BiometricPrompt` API.
     *
     * On successful authentication, the `onSuccessAuthenticateEncryptSecureBiometric` callback is triggered with the cipher and encoded IV.
     * If an error occurs or authentication fails, appropriate error and failure callbacks will be triggered.
     *
     * @param alias The alias used to retrieve the secret key from the Android keystore.
     * @param title The title of the biometric prompt displayed to the user.
     * @param description A description message for the biometric prompt, explaining the purpose of authentication.
     * @param negativeText The text for the negative button (cancel button) in the biometric prompt.
     * @param cancellationSignal A signal to cancel the authentication if needed, such as when the user cancels the operation.
     * @param callBack The callback interface to handle success, failure, and error scenarios during the authentication process.
     *
     * The following events are handled through the callback:
     * - **onSuccessAuthenticateEncryptSecureBiometric(cipher: Cipher, encodedIvKey: String)**: Called when authentication is successful and encryption can proceed. The cipher and its initialization vector (IV) are provided.
     * - **onFailedAuthenticate()**: Called when authentication fails (e.g., user did not pass biometric validation).
     * - **onErrorAuthenticate(exception: FeatureBiometricException)**: Called when an error occurs, such as an issue with the cipher or the authentication process.
     *
     * Example usage for encryption:
     *
     * ```kotlin
     * authenticateSecureEncrypt(
     *     alias = "myKeyAlias",
     *     title = "Secure Login",
     *     description = "Authenticate to encrypt your data",
     *     negativeText = "Cancel",
     *     cancellationSignal = CancellationSignal(),
     *     callBack = myBiometricCallback
     * )
     * ```
     */
    fun authenticateSecureEncrypt(
        alias: String,
        title: String,
        description: String,
        negativeText: String,
        cancellationSignal: CancellationSignal,
        callBack: FeatureBiometricEncryptSecureCallBack,
    ) {
        val executor = ContextCompat.getMainExecutor(activity)
        val cipher = getCipher()
        var secretKey = getSecretKey(alias)
        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        } catch (e: Exception) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (e is KeyPermanentlyInvalidatedException) {
                    Log.w(
                        KotlinFeatureBiometric::class.java.simpleName,
                        "alias key $alias is already invalid, try to delete secret key & re init again"
                    )
                    deleteSecretKey(alias)
                    secretKey = getSecretKey(alias)
                    try {
                        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
                    } catch (e: KeyPermanentlyInvalidatedException) {
                        Log.e(
                            KotlinFeatureBiometric::class.java.simpleName,
                            "alias key $alias is already invalid"
                        )
                        return
                    }
                }
            } else {
                callBack.onErrorAuthenticate(
                    FeatureBiometricException(
                        code = "INIT_CIPHER",
                        message = e.message
                    )
                )
                return
            }
        }

        when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P -> {
                val biometricPrompt = getBiometricPromptP(
                    activity = activity,
                    title = title,
                    description = description,
                    negativeText = negativeText,
                    executor = executor,
                    type = BiometricType.STRONG,
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
                    type = BiometricType.STRONG,
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

    /**
     * Initiates a secure biometric authentication process for decryption using the provided alias and encoded IV Key.
     *
     * This function sets up and prompts the user for biometric authentication (or device credentials, depending on the device’s support).
     * If authentication succeeds, the provided cipher will be initialized for decryption.
     *
     * The function adapts the authentication mechanism based on the device's Android version:
     *
     * - **Android P (API 28) and above**: Uses the updated `BiometricPrompt` API for stronger biometric security.
     * - **Android below P**: Uses the older `androidx.biometric.BiometricPrompt` API.
     *
     * On successful authentication, the `onSuccessAuthenticateDecryptSecureBiometric` callback is triggered with the cipher.
     * If an error occurs or authentication fails, appropriate error and failure callbacks will be triggered.
     *
     * @param alias The alias used to retrieve the secret key from the Android keystore.
     * @param encodedIvKey The iv key used for decryption.
     * @param title The title of the biometric prompt displayed to the user.
     * @param description A description message for the biometric prompt, explaining the purpose of authentication.
     * @param negativeText The text for the negative button (cancel button) in the biometric prompt.
     * @param cancellationSignal A signal to cancel the authentication if needed, such as when the user cancels the operation.
     * @param callBack The callback interface to handle success, failure, and error scenarios during the authentication process.
     *
     * The following events are handled through the callback:
     * - **onSuccessAuthenticateEncryptSecureBiometric(cipher: Cipher, encodedIvKey: String)**: Called when authentication is successful and encryption can proceed. The cipher and its initialization vector (IV) are provided.
     * - **onFailedAuthenticate()**: Called when authentication fails (e.g., user did not pass biometric validation).
     * - **onErrorAuthenticate(exception: FeatureBiometricException)**: Called when an error occurs, such as an issue with the cipher or the authentication process.
     *
     * Example usage for encryption:
     *
     * ```kotlin
     * authenticateSecureDecrypt(
     *     alias = "myKeyAlias",
     *     encodedIvKey = myEncodedIvKey,
     *     title = "Secure Login",
     *     description = "Authenticate to encrypt your data",
     *     negativeText = "Cancel",
     *     cancellationSignal = CancellationSignal(),
     *     callBack = myBiometricCallback
     * )
     * ```
     */
    fun authenticateSecureDecrypt(
        alias: String,
        encodedIvKey: String,
        title: String,
        description: String,
        negativeText: String,
        cancellationSignal: CancellationSignal,
        callBack: FeatureBiometricDecryptSecureCallBack,
    ) {
        val executor = ContextCompat.getMainExecutor(activity)
        val cipher = getCipher()
        val secretKey = getSecretKey(alias)
        try {
            val ivKey = Base64.decode(encodedIvKey, Base64.NO_WRAP)
            val ivSpec = IvParameterSpec(ivKey)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
        } catch (e: Exception) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (e is KeyPermanentlyInvalidatedException) {
                    callBack.onErrorAuthenticate(
                        FeatureBiometricException(
                            code = "KEY_PERMANENTLY_INVALID_EXCEPTION",
                            message = "The provided key is permanently invalid. Please register a new key again.",
                        )
                    )
                    return
                }
            }
            callBack.onErrorAuthenticate(
                FeatureBiometricException(
                    code = "INIT_CIPHER",
                    message = "The provided key is permanently invalid. Please register a new key again.",
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
                    type = BiometricType.STRONG,
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
                    type = BiometricType.STRONG,
                    negativeText = negativeText
                )

                val biometricPrompt = getAndroidXBiometricPrompt(
                    fragmentActivity = activity as FragmentActivity,
                    executor = executor,
                    callBack = object :
                        androidx.biometric.BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: androidx.biometric.BiometricPrompt.AuthenticationResult) {
                            super.onAuthenticationSucceeded(result)
                            callBack.onSuccessAuthenticateDecryptSecureBiometric(cipher = cipher)
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

    /**
     * Initiates a biometric authentication process.
     *
     * This function sets up and prompts the user for biometric authentication (or device credentials, depending on the device’s support).
     * If authentication succeeds, the provided cipher will be initialized for decryption.
     *
     * The function adapts the authentication mechanism based on the device's Android version:
     *
     * - **Android P (API 28) and above**: Uses the updated `BiometricPrompt` API for stronger biometric security.
     * - **Android below P**: Uses the older `androidx.biometric.BiometricPrompt` API.
     *
     * On successful authentication, the `onSuccessAuthenticate` callback is triggered.
     * If an error occurs or authentication fails, appropriate error and failure callbacks will be triggered.
     *
     * @param type The type of biometric, it could be BiometricType.WEAK
     * @param title The title of the biometric prompt displayed to the user.
     * @param description A description message for the biometric prompt, explaining the purpose of authentication.
     * @param negativeText The text for the negative button (cancel button) in the biometric prompt.
     * @param cancellationSignal A signal to cancel the authentication if needed, such as when the user cancels the operation.
     * @param callBack The callback interface to handle success, failure, and error scenarios during the authentication process.
     *
     * The following events are handled through the callback:
     * - **onSuccessAuthenticate()**: Called when authentication is successful.
     * - **onFailedAuthenticate()**: Called when authentication fails (e.g., user did not pass biometric validation).
     * - **onErrorAuthenticate(exception: FeatureBiometricException)**: Called when an error occurs, such as an issue with the cipher or the authentication process.
     *
     * Example usage for encryption:
     *
     * ```kotlin
     * authenticate(
     *     type = BiometricType.WEAK,
     *     alias = "myKeyAlias",
     *     title = "Secure Login",
     *     description = "Authenticate to encrypt your data",
     *     negativeText = "Cancel",
     *     cancellationSignal = CancellationSignal(),
     *     callBack = myBiometricCallback
     * )
     * ```
     */
    fun authenticate(
        type: BiometricType,
        cancellationSignal: CancellationSignal,
        title: String,
        description: String,
        negativeText: String,
        callBack: FeatureBiometricCallBack,
    ) {
        val executor = ContextCompat.getMainExecutor(activity)
        when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P -> {
                val biometricPrompt = getBiometricPromptP(
                    activity = activity,
                    title = title,
                    description = description,
                    negativeText = negativeText,
                    executor = executor,
                    type = type,
                    listener = { dialog, which -> callBack.onDialogClick(dialog, which) },
                )

                biometricPrompt.authenticate(
                    cancellationSignal,
                    executor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
                            super.onAuthenticationSucceeded(result)
                            callBack.onSuccessAuthenticate()
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
                    type = type,
                    negativeText = negativeText
                )

                val biometricPrompt = getAndroidXBiometricPrompt(
                    fragmentActivity = activity as FragmentActivity,
                    executor = executor,
                    callBack = object :
                        androidx.biometric.BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: androidx.biometric.BiometricPrompt.AuthenticationResult) {
                            super.onAuthenticationSucceeded(result)
                            callBack.onSuccessAuthenticate()
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
                biometricPrompt.authenticate(promptInfo)
            }
        }
    }

    /**
     * Encrypts a plain text string using the provided cipher.
     *
     * This function takes a `Cipher` initialized for encryption and the plain text to be encrypted.
     * It encrypts the plain text and returns the result as a Base64-encoded string without any extra
     * wrapping or padding.
     *
     * @param cipher The `Cipher` instance initialized in `ENCRYPT_MODE`.
     * @param plainText The plain text string to be encrypted.
     * @return The Base64-encoded encrypted string.
     */
    fun encrypt(cipher: Cipher, plainText: String): String {
        val byteEncryptedPassword = cipher.doFinal(plainText.toByteArray())
        return Base64.encodeToString(byteEncryptedPassword, Base64.NO_WRAP)
    }

    /**
     * Decrypts an encrypted byte array using the provided cipher.
     *
     * This function takes a `Cipher` initialized for decryption and the encrypted byte array.
     * It decrypts the byte array and returns the original plain text string. If decryption fails
     * due to incorrect padding, a `FeatureBiometricException` is thrown with the appropriate error message.
     *
     * @param cipher The `Cipher` instance initialized in `DECRYPT_MODE`.
     * @param encryptedPassword The encrypted byte array to be decrypted.
     * @return The decrypted plain text string.
     * @throws FeatureBiometricException If the decryption fails due to padding issues (BadPaddingException).
     */
    fun decrypt(cipher: Cipher, encryptedPassword: ByteArray): String {
        try {
            return String(cipher.doFinal(encryptedPassword))
        } catch (e: BadPaddingException) {
            throw FeatureBiometricException(
                code = "BAD_PADDING_EXCEPTION",
                message = e.message,
            )
        }
    }

    /**
     * Decrypts an encrypted Base64-encoded string using the provided cipher.
     *
     * This function takes a `Cipher` initialized for decryption and a Base64-encoded encrypted string.
     * It decodes the encrypted string from Base64 to a byte array, and then decrypts it using the
     * `decrypt(cipher, encryptedPassword: ByteArray)` function.
     *
     * @param cipher The `Cipher` instance initialized in `DECRYPT_MODE`.
     * @param encryptedPassword The Base64-encoded encrypted string to be decrypted.
     * @return The decrypted plain text string.
     * @throws FeatureBiometricException If the decryption fails due to padding issues.
     */
    fun decrypt(cipher: Cipher, encryptedPassword: String): String {
        val decodedPassword =
            Base64.decode(encryptedPassword, Base64.NO_WRAP)
        return decrypt(cipher = cipher, encryptedPassword = decodedPassword)
    }
}