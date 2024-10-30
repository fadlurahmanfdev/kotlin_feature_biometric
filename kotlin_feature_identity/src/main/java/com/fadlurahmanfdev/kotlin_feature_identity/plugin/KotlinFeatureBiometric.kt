package com.fadlurahmanfdev.kotlin_feature_identity.plugin

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
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
import com.fadlurahmanfdev.kotlin_feature_identity.constant.KotlinFeatureErrorAuthentication
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.FeatureBiometricCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.FeatureBiometricDecryptSecureCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.FeatureBiometricEncryptSecureCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureAuthenticatorType
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureAuthenticationStatus
import com.fadlurahmanfdev.kotlin_feature_identity.data.exception.FeatureBiometricException
import java.security.KeyStore
import java.util.concurrent.Executor
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class KotlinFeatureBiometric(private val activity: Activity) : KotlinFeatureBiometricRepository {
    companion object {
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

        private fun getSecretKey(alias: String): SecretKey? {
            var secretKey: SecretKey? = null
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            try {
                val existingSecretKey =
                    keyStore.getKey(alias, null) as SecretKey?
                if (existingSecretKey != null) {
                    Log.d(
                        this::class.java.simpleName,
                        "successfully use existing key - $alias"
                    )
                    secretKey = existingSecretKey
                }
            } catch (e: Exception) {
                Log.d(
                    this::class.java.simpleName,
                    "failed get existing key $alias: ${e.message}"
                )
                throw FeatureBiometricException(
                    code = KotlinFeatureErrorAuthentication.GENERAL_01,
                    message = e.message
                )
            }

            return secretKey
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

        @RequiresApi(Build.VERSION_CODES.P)
        private fun getBiometricPromptAndroidP(
            activity: Activity,
            authenticator: Int,
            title: String,
            description: String,
            negativeText: String,
            executor: Executor,
            listener: OnClickListener,
        ): BiometricPrompt {
            return BiometricPrompt.Builder(activity).setTitle(title).setDescription(description)
                .apply {
                    when (authenticator) {
                        Authenticators.BIOMETRIC_WEAK -> {
                            setNegativeButton(negativeText, executor, listener)
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                setAllowedAuthenticators(Authenticators.BIOMETRIC_WEAK)
                            }
                        }

                        Authenticators.BIOMETRIC_STRONG -> {
                            setNegativeButton(negativeText, executor, listener)
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG)
                            }
                        }

                        Authenticators.DEVICE_CREDENTIAL -> {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                setAllowedAuthenticators(Authenticators.DEVICE_CREDENTIAL)
                            }
                        }
                    }
                }.build()
        }

        private fun getPromptInfoAndroidLollipop(
            title: String,
            authenticator: Int,
            description: String,
            negativeText: String,
        ): androidx.biometric.BiometricPrompt.PromptInfo {
            return androidx.biometric.BiometricPrompt.PromptInfo.Builder().setTitle(title)
                .setDescription(description).setNegativeButtonText(negativeText)
                .apply {
                    when (authenticator) {
                        BiometricManager.Authenticators.BIOMETRIC_WEAK -> {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_WEAK)
                            }
                        }

                        BiometricManager.Authenticators.BIOMETRIC_STRONG -> {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                            }
                        }

                        BiometricManager.Authenticators.DEVICE_CREDENTIAL -> {
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                setAllowedAuthenticators(BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                            }
                        }
                    }
                }
                .build()
        }

        private fun getBiometricPromptAndroidLollipop(
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

    private fun validateAuthenticateStatus(type: FeatureAuthenticatorType) {
        val authenticationStatus = checkAuthenticationStatus(type)
        val canAuthenticate = authenticationStatus == FeatureAuthenticationStatus.SUCCESS
        if (!canAuthenticate) {
            throw FeatureBiometricException(
                code = KotlinFeatureErrorAuthentication.CANT_AUTHENTICATE,
                message = "Cannot authenticate using $type because $authenticationStatus"
            )
        }
    }

    /**
     * This is the step where user should generate secret key before user can use authenticate secure encrypt/decrypt.
     *
     * User no need to know the secret key, and therefore, its not return any value.
     *
     * @param alias the alias of the secret key
     *
     * @throws KotlinFeatureErrorAuthentication.KEY_PERMANENTLY_INVALIDATED if new biometric/changed biometric detected.
     * @throws KotlinFeatureErrorAuthentication.GENERAL_00 if general exception happen.
     */
    override fun generateSecretKey(alias: String) {
        val cipher = getCipher()
        var secretKey: SecretKey? = getSecretKey(alias)

        if (secretKey != null) {
            Log.d(this::class.java.simpleName, "secret key $alias already exist")
            return
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val keyGenerator =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            keyGenerator.init(generateKeyGenParameterSpec(alias))
            secretKey = keyGenerator.generateKey()
        } else {
            val keyGenerator = KeyGenerator.getInstance("AES")
            keyGenerator.init(256)
            secretKey = keyGenerator.generateKey()
        }

        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        } catch (e: Exception) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (e is KeyPermanentlyInvalidatedException) {
                    throw FeatureBiometricException(
                        code = KotlinFeatureErrorAuthentication.KEY_PERMANENTLY_INVALIDATED,
                        message = e.message
                    )
                }
            }
            throw FeatureBiometricException(
                code = KotlinFeatureErrorAuthentication.GENERAL_00,
                message = e.message
            )
        }
    }

    override fun deleteSecretKey(alias: String) {
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

    /**
     * Determines the device's support biometric feature, either fingerprint or face authentication.
     *
     * @return true, if device support biometric, otherwise is false.
     */
    override fun isDeviceSupportBiometric(): Boolean {
        var isHaveFingerprint = false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            isHaveFingerprint =
                activity.packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)
        }
        val isHaveFaceAuth = isDeviceSupportFaceAuthentication()
        return isHaveFingerprint || isHaveFaceAuth
    }

    /**
     * Determines the device's support face authentication.
     *
     * @return true, if device support face authentication, otherwise is false.
     */
    override fun isDeviceSupportFaceAuthentication(): Boolean {
        val isHaveFaceAuth = false

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            activity.packageManager.hasSystemFeature(PackageManager.FEATURE_FACE)
        }

        if (!isHaveFaceAuth) {
            activity.packageManager.hasSystemFeature("com.samsung.android.bio.face")
        }

        return isHaveFaceAuth
    }

    /**
     * Determines the device's can authenticate using biometric
     *
     * @return The boolean indicate which the device can authenticate using biometric
     */
    override fun canAuthenticate(type: FeatureAuthenticatorType): Boolean {
        return checkAuthenticationStatus(type) == FeatureAuthenticationStatus.SUCCESS
    }

    /**
     * Determines the device's ability to authenticate using biometrics or device credentials.
     *
     * This function uses the `BiometricManager` to check the current biometric and device credential
     * authentication capabilities and returns a corresponding `CanAuthenticateReasonType` value.
     *
     * It checks for the following authentication states:
     *
     * - `FeatureAuthenticationStatus.SUCCESS`: Biometric authentication is available and the user is enrolled.
     * - `FeatureAuthenticationStatus.NO_BIOMETRIC_AVAILABLE`: No biometric hardware is available on the device.
     * - `FeatureAuthenticationStatus.BIOMETRIC_UNAVAILABLE`: Biometric hardware is temporarily unavailable (e.g., being used by another process).
     * - `FeatureAuthenticationStatus.NONE_ENROLLED`: Biometric hardware is available, but the user has not enrolled any biometric credentials.
     * - `FeatureAuthenticationStatus.UNKNOWN`: An unknown error occurred during the authentication capability check.
     *
     * If the function returns `FeatureAuthenticationStatus.NONE_ENROLLED`, you can guide the user to enroll their biometrics
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
    override fun checkAuthenticationStatus(type: FeatureAuthenticatorType): FeatureAuthenticationStatus {
        val authenticators: Int = when (type) {
            FeatureAuthenticatorType.BIOMETRIC -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    BiometricManager.Authenticators.BIOMETRIC_WEAK
                } else {
                    BiometricManager.Authenticators.BIOMETRIC_WEAK
                }
            }

            FeatureAuthenticatorType.DEVICE_CREDENTIAL -> {
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
            }
        }
        val biometricManager = androidx.biometric.BiometricManager.from(activity)
        return when (biometricManager.canAuthenticate(authenticators)) {
            androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS ->
                FeatureAuthenticationStatus.SUCCESS

            androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE ->
                FeatureAuthenticationStatus.NO_HARDWARE

            androidx.biometric.BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
                FeatureAuthenticationStatus.UNAVAILABLE

            androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                FeatureAuthenticationStatus.NONE_ENROLLED
            }

            else -> {
                FeatureAuthenticationStatus.UNKNOWN
            }
        }
    }

    /**
     * Detect whether the biometric changed.
     *
     * this function return true if the biometric added into a device.
     *
     * @param alias The alias used to retrieve the secret key from the Android keystore.
     *
     * Example usage for encryption:
     *
     * ```kotlin
     * val isBiometricChanged = isBiometricChanged(
     *     alias = "myKeyAlias",
     * )
     * ```
     */
    override fun isBiometricChanged(alias: String): Boolean {
        val cipher = getCipher()
        val secretKey = getSecretKey(alias)
            ?: throw FeatureBiometricException(
                code = KotlinFeatureErrorAuthentication.SECRET_KEY_MISSING,
                message = "Cannot check whether biometric changed because the secret key is missing"
            )

        try {
            cipher.init(Cipher.DECRYPT_MODE, secretKey)
        } catch (e: Exception) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (e is KeyPermanentlyInvalidatedException) {
                    return true
                }
            } else {
                throw FeatureBiometricException(
                    code = KotlinFeatureErrorAuthentication.GENERAL_02,
                    e.message
                )
            }
        }
        return false
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
    override fun authenticate(
        type: FeatureAuthenticatorType,
        cancellationSignal: CancellationSignal,
        title: String,
        description: String,
        negativeText: String,
        callBack: FeatureBiometricCallBack,
    ) {
        val authenticator = when (type) {
            FeatureAuthenticatorType.BIOMETRIC -> {
                BiometricManager.Authenticators.BIOMETRIC_WEAK
            }

            FeatureAuthenticatorType.DEVICE_CREDENTIAL -> {
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
            }
        }

        validateAuthenticateStatus(type)

        val keyguardManager = activity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        val executor = ContextCompat.getMainExecutor(activity)
        when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P -> {
                val biometricPrompt = getBiometricPromptAndroidP(
                    activity = activity,
                    title = title,
                    description = description,
                    negativeText = negativeText,
                    executor = executor,
                    authenticator = authenticator,
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
                            if (errorCode == 10) {
                                callBack.onCanceled();
                            } else {
                                callBack.onErrorAuthenticate(
                                    FeatureBiometricException(
                                        code = "$errorCode",
                                        message = errString?.toString()
                                    )
                                )
                            }
                        }
                    },
                )
            }

            else -> {
                val promptInfo = getPromptInfoAndroidLollipop(
                    title = title,
                    description = description,
                    authenticator = authenticator,
                    negativeText = negativeText
                )

                val biometricPrompt = getBiometricPromptAndroidLollipop(
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
                            if (errorCode == 10) {
                                callBack.onCanceled();
                            } else {
                                callBack.onErrorAuthenticate(
                                    FeatureBiometricException(
                                        code = "$errorCode",
                                        message = errString.toString()
                                    )
                                )
                            }
                        }
                    }
                )
                biometricPrompt.authenticate(promptInfo)
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
    override fun authenticateSecureEncrypt(
        alias: String,
        title: String,
        description: String,
        negativeText: String,
        cancellationSignal: CancellationSignal,
        callBack: FeatureBiometricEncryptSecureCallBack,
    ) {
        try {
            val executor = ContextCompat.getMainExecutor(activity)
            val cipher = getCipher()
            val secretKey = getSecretKey(alias)
                ?: throw FeatureBiometricException(
                    code = KotlinFeatureErrorAuthentication.SECRET_KEY_MISSING,
                    message = "Cannot authenticate secure encrypt because the secret key is missing"
                )

            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.P -> {
                    val biometricPrompt = getBiometricPromptAndroidP(
                        activity = activity,
                        title = title,
                        description = description,
                        negativeText = negativeText,
                        executor = executor,
                        authenticator = BiometricManager.Authenticators.BIOMETRIC_STRONG,
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
                                            code = KotlinFeatureErrorAuthentication.CIPHER_MISSING,
                                            message = "Cannot encrypt because the cipher is missing"
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
                                if (errorCode == 10) {
                                    callBack.onCanceled()
                                } else {
                                    callBack.onErrorAuthenticate(
                                        FeatureBiometricException(
                                            code = "$errorCode",
                                            message = errString?.toString()
                                        )
                                    )
                                }
                            }
                        },
                    )
                }

                else -> {
                    val promptInfo = getPromptInfoAndroidLollipop(
                        title = title,
                        description = description,
                        authenticator = BiometricManager.Authenticators.BIOMETRIC_STRONG,
                        negativeText = negativeText
                    )

                    val biometricPrompt = getBiometricPromptAndroidLollipop(
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
                                            code = KotlinFeatureErrorAuthentication.CIPHER_MISSING,
                                            message = "Cannot encrypt because the cipher is missing"
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
                                if (errorCode == 10) {
                                    callBack.onCanceled()
                                } else {
                                    callBack.onErrorAuthenticate(
                                        FeatureBiometricException(
                                            code = "$errorCode",
                                            message = errString.toString()
                                        )
                                    )
                                }
                            }
                        }
                    )
                    biometricPrompt.authenticate(
                        promptInfo,
                        androidx.biometric.BiometricPrompt.CryptoObject(cipher)
                    )
                }
            }
        } catch (e: FeatureBiometricException) {
            callBack.onErrorAuthenticate(e)
        } catch (e: Exception) {
            callBack.onErrorAuthenticate(
                FeatureBiometricException(
                    code = KotlinFeatureErrorAuthentication.GENERAL_03,
                    message = e.message
                )
            )
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
    override fun authenticateSecureDecrypt(
        alias: String,
        encodedIvKey: String,
        title: String,
        description: String,
        negativeText: String,
        cancellationSignal: CancellationSignal,
        callBack: FeatureBiometricDecryptSecureCallBack,
    ) {
        try {
            val executor = ContextCompat.getMainExecutor(activity)
            val cipher = getCipher()
            val secretKey = getSecretKey(alias) ?: throw FeatureBiometricException(
                code = KotlinFeatureErrorAuthentication.SECRET_KEY_MISSING,
                message = "Cannot authenticate secure decrypt because the secret key is missing"
            )
            try {
                val ivKey = Base64.decode(encodedIvKey, Base64.NO_WRAP)
                val ivSpec = IvParameterSpec(ivKey)
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
            } catch (e: Exception) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    if (e is KeyPermanentlyInvalidatedException) {
                        throw FeatureBiometricException(
                            code = KotlinFeatureErrorAuthentication.KEY_PERMANENTLY_INVALIDATED,
                            message = "The provided key is permanently invalid. Please register a new key again."
                        )
                    }
                }
                throw FeatureBiometricException(
                    code = KotlinFeatureErrorAuthentication.GENERAL_04,
                    message = e.message,
                )
            }

            when {
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.P -> {
                    val biometricPrompt = getBiometricPromptAndroidP(
                        activity = activity,
                        title = title,
                        description = description,
                        negativeText = negativeText,
                        executor = executor,
                        authenticator = BiometricManager.Authenticators.BIOMETRIC_STRONG,
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
                                            code = KotlinFeatureErrorAuthentication.CIPHER_MISSING,
                                            message = "Cannot decrypt because the cipher is missing"
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
                                if (errorCode == 10) {
                                    callBack.onCanceled()
                                } else {
                                    callBack.onErrorAuthenticate(
                                        FeatureBiometricException(
                                            code = "$errorCode",
                                            message = errString?.toString()
                                        )
                                    )
                                }
                            }
                        },
                    )
                }

                else -> {
                    val promptInfo = getPromptInfoAndroidLollipop(
                        title = title,
                        description = description,
                        authenticator = BiometricManager.Authenticators.BIOMETRIC_STRONG,
                        negativeText = negativeText
                    )

                    val biometricPrompt = getBiometricPromptAndroidLollipop(
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
                                if (errorCode == 10) {
                                    callBack.onCanceled()
                                } else {
                                    callBack.onErrorAuthenticate(
                                        FeatureBiometricException(
                                            code = "$errorCode",
                                            message = errString.toString()
                                        )
                                    )
                                }
                            }
                        }
                    )
                    biometricPrompt.authenticate(
                        promptInfo,
                        androidx.biometric.BiometricPrompt.CryptoObject(cipher)
                    )
                }
            }
        } catch (e: FeatureBiometricException) {
            callBack.onErrorAuthenticate(e)
        } catch (e: Exception) {
            callBack.onErrorAuthenticate(
                FeatureBiometricException(
                    code = KotlinFeatureErrorAuthentication.GENERAL_05,
                    message = e.message
                )
            )
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
        val byteEncryptedText = cipher.doFinal(plainText.toByteArray())
        return Base64.encodeToString(byteEncryptedText, Base64.NO_WRAP)
    }

    /**
     * Decrypts an encrypted byte array using the provided cipher.
     *
     * This function takes a `Cipher` initialized for decryption and the encrypted byte array.
     * It decrypts the byte array and returns the original plain text string. If decryption fails
     * due to incorrect padding, a `FeatureBiometricException` is thrown with the appropriate error message.
     *
     * @param cipher The `Cipher` instance initialized in `DECRYPT_MODE`.
     * @param encryptedText The encrypted byte array to be decrypted.
     * @return The decrypted plain text string.
     * @throws FeatureBiometricException If the decryption fails due to padding issues (BadPaddingException).
     */
    fun decrypt(cipher: Cipher, encryptedText: ByteArray): String {
        try {
            return String(cipher.doFinal(encryptedText))
        } catch (e: BadPaddingException) {
            throw FeatureBiometricException(
                code = KotlinFeatureErrorAuthentication.BAD_PADDING,
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
     * @param encryptedText The Base64-encoded encrypted string to be decrypted.
     * @return The decrypted plain text string.
     * @throws FeatureBiometricException If the decryption fails due to padding issues.
     */
    fun decrypt(cipher: Cipher, encryptedText: String): String {
        val decodedText =
            Base64.decode(encryptedText, Base64.NO_WRAP)
        return decrypt(cipher = cipher, encryptedText = decodedText)
    }
}