package com.fadlurahmanfdev.kotlin_feature_identity.plugin

import android.app.KeyguardManager
import android.content.Context
import android.content.DialogInterface
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.hardware.biometrics.BiometricPrompt.CryptoObject
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import com.fadlurahmanfdev.kotlin_feature_identity.constant.ErrorConstant
import com.fadlurahmanfdev.kotlin_feature_identity.constant.KotlinFeatureErrorAuthentication
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.AuthenticationCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.SecureAuthenticationDecryptCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.SecureAuthenticationEncryptCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.CheckAuthenticationStatusType
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureAuthenticationStatus
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureAuthenticatorType
import com.fadlurahmanfdev.kotlin_feature_identity.data.exception.FeatureBiometricException
import com.fadlurahmanfdev.kotlin_feature_identity.data.exception.FeatureIdentityException
import java.security.KeyStore
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class FeatureAuthentication(private val context: Context) : FeatureAuthenticationRepository {

    private lateinit var fingerprintManager: FingerprintManager
    private lateinit var biometricManager: BiometricManager
    private lateinit var keyguardManager: KeyguardManager

    init {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            fingerprintManager =
                context.getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            biometricManager =
                context.getSystemService(Context.BIOMETRIC_SERVICE) as BiometricManager
        }

        keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
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

    private fun generateSecretKey(alias: String): SecretKey {
        var secretKey: SecretKey? = getSecretKey(alias)

        if (secretKey != null) {
            Log.d(this::class.java.simpleName, "secret key $alias already exist")
            return secretKey
        }

        Log.d(this::class.java.simpleName, "generating new secret key $alias")
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

        return secretKey
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
                    "successfully get existing key - $alias"
                )
                secretKey = existingSecretKey
            }
        } catch (e: Exception) {
            Log.d(
                this::class.java.simpleName,
                "unable to fetch $alias: ${e.message}"
            )
            throw FeatureIdentityException(
                code = ErrorConstant.UNABLE_FETCH_GET_SECRET_KEY,
                message = e.message
            )
        }
        return secretKey
    }

    override fun deleteSecretKey(alias: String) {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        try {
            keyStore.deleteEntry(alias)
            Log.d(
                this::class.java.simpleName,
                "successfully delete secret key $alias"
            )
        } catch (e: Exception) {
            Log.e(
                this::class.java.simpleName,
                "failed to delete secret key $alias"
            )
            throw FeatureIdentityException(
                code = ErrorConstant.UNABLE_TO_DELETE_SECRET_KEY,
                message = e.message
            )
        }
    }

    override fun isDeviceSupportFingerprint(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return context.packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return fingerprintManager.isHardwareDetected
        }

        return false
    }

    override fun isDeviceSupportFaceAuth(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return context.packageManager.hasSystemFeature(PackageManager.FEATURE_FACE) || context.packageManager.hasSystemFeature(
                "com.samsung.android.bio.face"
            )
        } else {
            return context.packageManager.hasSystemFeature(
                "com.samsung.android.bio.face"
            )
        }
    }

    override fun isDeviceSupportBiometric(): Boolean {
        return (isDeviceSupportFingerprint() || isDeviceSupportFaceAuth())
    }

    @RequiresApi(Build.VERSION_CODES.M)
    override fun isFingerprintEnrolled(): Boolean {
        return fingerprintManager.hasEnrolledFingerprints()
    }

    @RequiresApi(Build.VERSION_CODES.M)
    override fun isDeviceCredentialEnrolled(): Boolean {
        return keyguardManager.isDeviceSecure
    }

    override fun checkAuthenticatorStatus(authenticatorType: FeatureAuthenticatorType): FeatureAuthenticationStatus {
        return when (authenticatorType) {
            FeatureAuthenticatorType.BIOMETRIC -> checkAuthenticationStatus(type = CheckAuthenticationStatusType.BIOMETRIC_WEAK)
            FeatureAuthenticatorType.DEVICE_CREDENTIAL -> checkAuthenticationStatus(type = CheckAuthenticationStatusType.DEVICE_CREDENTIAL)
        }
    }

    override fun checkSecureAuthentication(): FeatureAuthenticationStatus {
        return checkAuthenticationStatus(type = CheckAuthenticationStatusType.BIOMETRIC_STRONG)
    }

    private fun checkAuthenticationStatus(
        type: CheckAuthenticationStatusType
    ): FeatureAuthenticationStatus {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val authenticatorType = when (type) {
                CheckAuthenticationStatusType.BIOMETRIC_WEAK -> BiometricManager.Authenticators.BIOMETRIC_WEAK
                CheckAuthenticationStatusType.BIOMETRIC_STRONG -> BiometricManager.Authenticators.BIOMETRIC_STRONG
                CheckAuthenticationStatusType.DEVICE_CREDENTIAL -> BiometricManager.Authenticators.DEVICE_CREDENTIAL
            }

            val authenticatorStatus =
                biometricManager.canAuthenticate(authenticatorType)
            return when (authenticatorStatus) {
                BiometricManager.BIOMETRIC_SUCCESS -> {
                    FeatureAuthenticationStatus.SUCCESS
                }

                BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                    FeatureAuthenticationStatus.NO_HARDWARE
                }

                BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                    FeatureAuthenticationStatus.UNAVAILABLE
                }

                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                    FeatureAuthenticationStatus.NONE_ENROLLED
                }

                BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> {
                    FeatureAuthenticationStatus.SECURITY_UPDATE_REQUIRED
                }

                else -> {
                    FeatureAuthenticationStatus.UNKNOWN
                }
            }
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            when (type) {
                CheckAuthenticationStatusType.BIOMETRIC_WEAK, CheckAuthenticationStatusType.BIOMETRIC_STRONG -> {
                    val isEnrolled = isFingerprintEnrolled()
                    return if (isEnrolled) {
                        FeatureAuthenticationStatus.SUCCESS
                    } else {
                        FeatureAuthenticationStatus.NONE_ENROLLED
                    }
                }

                CheckAuthenticationStatusType.DEVICE_CREDENTIAL -> {
                    val isEnrolled = isDeviceCredentialEnrolled()
                    return if (isEnrolled) {
                        FeatureAuthenticationStatus.SUCCESS
                    } else {
                        FeatureAuthenticationStatus.NONE_ENROLLED
                    }
                }
            }
        }

        return FeatureAuthenticationStatus.UNSUPPORTED_OS_VERSION
    }

    override fun canAuthenticate(authenticatorType: FeatureAuthenticatorType): Boolean {
        return checkAuthenticatorStatus(authenticatorType) == FeatureAuthenticationStatus.SUCCESS
    }

    @RequiresApi(Build.VERSION_CODES.R)
    override fun authenticateDeviceCredential(
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: AuthenticationCallBack
    ) {
        generalAuthenticateBiometricAndroidP(
            title = title,
            subTitle = subTitle,
            description = description,
            authenticator = BiometricManager.Authenticators.DEVICE_CREDENTIAL,
            negativeText = negativeText,
            negativeButtonCallback = object : DialogInterface.OnClickListener {
                override fun onClick(dialog: DialogInterface?, which: Int) {
                    callBack.onNegativeButtonClicked(which)
                }
            },
            cryptoObject = null,
            callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
                    super.onAuthenticationSucceeded(result)
                    callBack.onSuccessAuthenticate()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    callBack.onFailedAuthenticate()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                    super.onAuthenticationError(errorCode, errString)
                    callBack.onErrorAuthenticate(
                        FeatureIdentityException(
                            code = "$errorCode",
                            message = errString?.toString()
                        )
                    )
                }
            }
        )
    }

    override fun authenticateBiometric(
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: AuthenticationCallBack
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            var authenticator = -1
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                authenticator = BiometricManager.Authenticators.BIOMETRIC_WEAK
            }
            generalAuthenticateBiometricAndroidP(
                title = title,
                subTitle = subTitle,
                description = description,
                authenticator = authenticator,
                setDeviceCredentialAllowed = true,
                negativeText = negativeText,
                negativeButtonCallback = object : DialogInterface.OnClickListener {
                    override fun onClick(dialog: DialogInterface?, which: Int) {
                        callBack.onNegativeButtonClicked(which)
                    }
                },
                cryptoObject = null,
                callback = object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
                        super.onAuthenticationSucceeded(result)
                        callBack.onSuccessAuthenticate()
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        callBack.onFailedAuthenticate()
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                        super.onAuthenticationError(errorCode, errString)
                        callBack.onErrorAuthenticate(
                            FeatureIdentityException(
                                code = "$errorCode",
                                message = errString?.toString()
                            )
                        )
                    }
                }
            )
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            generalAuthenticateAndroidM(
                null,
                object : FingerprintManager.AuthenticationCallback() {
                    @Deprecated("Deprecated in Java")
                    override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?) {
                        super.onAuthenticationSucceeded(result)
                        callBack.onSuccessAuthenticate()
                    }

                    @Deprecated("Deprecated in Java")
                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        callBack.onFailedAuthenticate()
                    }

                    @Deprecated("Deprecated in Java")
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                        super.onAuthenticationError(errorCode, errString)
                        callBack.onErrorAuthenticate(
                            FeatureIdentityException(
                                code = "$errorCode",
                                message = errString?.toString(),
                            )
                        )
                    }
                }
            )
        } else {
            throw FeatureIdentityException(
                code = ErrorConstant.OS_NOT_SUPPORTED,
                message = "OS not supported"
            )
        }
    }

    override fun isBiometricChanged(alias: String): Boolean {
        try {
            val cipher = getCipher()
            val secretKey = getSecretKey(alias = alias)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            return false
        } catch (e: FeatureIdentityException) {
            throw e
        } catch (e: Exception) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (e is KeyPermanentlyInvalidatedException) {
                    return true
                }
            }
            throw FeatureIdentityException(
                code = ErrorConstant.UNABLE_TO_DETECT_BIOMETRIC_CHANGE,
                message = e.message,
            )
        }
    }

    override fun secureAuthenticateBiometricEncrypt(
        alias: String,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: SecureAuthenticationEncryptCallBack
    ) {
        try {
            val cipher = getCipher()
            var secretKey = getSecretKey(alias = alias)

            if (secretKey == null) {
                secretKey = generateSecretKey(alias)
            }

            cipher.init(Cipher.ENCRYPT_MODE, secretKey)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                generalAuthenticateBiometricAndroidP(
                    title = title,
                    subTitle = subTitle,
                    description = description,
                    setDeviceCredentialAllowed = false,
                    authenticator = BiometricManager.Authenticators.BIOMETRIC_STRONG,
                    negativeText = negativeText,
                    negativeButtonCallback = object : DialogInterface.OnClickListener {
                        override fun onClick(dialog: DialogInterface?, which: Int) {
                            callBack.onNegativeButtonClicked(which)
                        }
                    },
                    cryptoObject = BiometricPrompt.CryptoObject(cipher),
                    callback = object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
                            super.onAuthenticationSucceeded(result)
                            if (result?.cryptoObject?.cipher == null) {
                                callBack.onErrorAuthenticate(
                                    FeatureIdentityException(
                                        code = ErrorConstant.CIPHER_MISSING,
                                        message = "Cipher missing for secure authentication"
                                    )
                                )
                                return
                            }

                            val cipherResult = result.cryptoObject.cipher
                            val encodedIvKey =
                                Base64.encodeToString(cipherResult.iv, Base64.NO_WRAP)
                            callBack.onSuccessAuthenticate(
                                cipherResult,
                                encodedIvKey
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
                                FeatureIdentityException(
                                    code = "$errorCode",
                                    message = errString?.toString()
                                )
                            )
                        }
                    }
                )
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                generalAuthenticateAndroidM(
                    FingerprintManager.CryptoObject(cipher),
                    object : FingerprintManager.AuthenticationCallback() {
                        @Deprecated("Deprecated in Java")
                        override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?) {
                            super.onAuthenticationSucceeded(result)
                            if (result?.cryptoObject?.cipher == null) {
                                callBack.onErrorAuthenticate(
                                    FeatureIdentityException(
                                        code = ErrorConstant.CIPHER_MISSING,
                                        message = "Cipher missing for secure authentication"
                                    )
                                )
                                return
                            }

                            val cipherResult = result.cryptoObject.cipher
                            val encodedIvKey =
                                Base64.encodeToString(cipherResult.iv, Base64.NO_WRAP)
                            callBack.onSuccessAuthenticate(
                                cipherResult,
                                encodedIvKey
                            )
                        }

                        @Deprecated("Deprecated in Java")
                        override fun onAuthenticationFailed() {
                            super.onAuthenticationFailed()
                            callBack.onFailedAuthenticate()
                        }

                        @Deprecated("Deprecated in Java")
                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence?
                        ) {
                            super.onAuthenticationError(errorCode, errString)
                            callBack.onErrorAuthenticate(
                                FeatureIdentityException(
                                    code = "$errorCode",
                                    message = errString?.toString(),
                                )
                            )
                        }
                    }
                )
            } else {
                throw FeatureIdentityException(
                    code = ErrorConstant.OS_NOT_SUPPORTED,
                    message = "OS not supported"
                )
            }
        } catch (e: FeatureIdentityException) {
            callBack.onErrorAuthenticate(e)
        } catch (e: KeyPermanentlyInvalidatedException) {
            callBack.onErrorAuthenticate(
                FeatureIdentityException(
                    code = ErrorConstant.KEY_PERMANENTLY_INVALIDATED,
                    message = e.message,
                )
            )
        } catch (e: Exception) {
            callBack.onErrorAuthenticate(
                FeatureIdentityException(
                    code = ErrorConstant.UNABLE_ENCRYPT_AUTHENTICATE,
                    message = e.message,
                )
            )
        }
    }

    override fun secureAuthenticateBiometricDecrypt(
        alias: String,
        encodedIVKey: String,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: SecureAuthenticationDecryptCallBack
    ) {
        try {
            val cipher = getCipher()
            val secretKey = getSecretKey(alias = alias)
                ?: throw FeatureIdentityException(
                    code = ErrorConstant.SECRET_KEY_MISSING,
                    message = "Cannot proceed to the next page caused by secret key null"
                )

            val ivKey = Base64.decode(encodedIVKey, Base64.NO_WRAP)
            val ivSpec = IvParameterSpec(ivKey)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                generalAuthenticateBiometricAndroidP(
                    title = title,
                    subTitle = subTitle,
                    description = description,
                    setDeviceCredentialAllowed = false,
                    authenticator = BiometricManager.Authenticators.BIOMETRIC_STRONG,
                    negativeText = negativeText,
                    negativeButtonCallback = object : DialogInterface.OnClickListener {
                        override fun onClick(dialog: DialogInterface?, which: Int) {
                            callBack.onNegativeButtonClicked(which)
                        }
                    },
                    cryptoObject = BiometricPrompt.CryptoObject(cipher),
                    callback = object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
                            super.onAuthenticationSucceeded(result)
                            if (result?.cryptoObject?.cipher == null) {
                                callBack.onErrorAuthenticate(
                                    FeatureIdentityException(
                                        code = ErrorConstant.CIPHER_MISSING,
                                        message = "Cipher missing for secure authentication"
                                    )
                                )
                                return
                            }

                            val cipherResult = result.cryptoObject.cipher
                            callBack.onSuccessAuthenticate(cipherResult)
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
                                FeatureIdentityException(
                                    code = "$errorCode",
                                    message = errString?.toString()
                                )
                            )
                        }
                    }
                )
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                generalAuthenticateAndroidM(
                    FingerprintManager.CryptoObject(cipher),
                    object : FingerprintManager.AuthenticationCallback() {
                        @Deprecated("Deprecated in Java")
                        override fun onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult?) {
                            super.onAuthenticationSucceeded(result)
                            if (result?.cryptoObject?.cipher == null) {
                                callBack.onErrorAuthenticate(
                                    FeatureIdentityException(
                                        code = ErrorConstant.CIPHER_MISSING,
                                        message = "Cipher missing for secure authentication"
                                    )
                                )
                                return
                            }

                            val cipherResult = result.cryptoObject.cipher
                            callBack.onSuccessAuthenticate(cipherResult)
                        }

                        @Deprecated("Deprecated in Java")
                        override fun onAuthenticationFailed() {
                            super.onAuthenticationFailed()
                            callBack.onFailedAuthenticate()
                        }

                        @Deprecated("Deprecated in Java")
                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence?
                        ) {
                            super.onAuthenticationError(errorCode, errString)
                            callBack.onErrorAuthenticate(
                                FeatureIdentityException(
                                    code = "$errorCode",
                                    message = errString?.toString(),
                                )
                            )
                        }
                    }
                )
            } else {
                throw FeatureIdentityException(
                    code = ErrorConstant.OS_NOT_SUPPORTED,
                    message = "OS not supported"
                )
            }
        } catch (e: FeatureIdentityException) {
            callBack.onErrorAuthenticate(e)
        } catch (e: KeyPermanentlyInvalidatedException) {
            callBack.onErrorAuthenticate(
                FeatureIdentityException(
                    code = ErrorConstant.KEY_PERMANENTLY_INVALIDATED,
                    message = e.message,
                )
            )
        } catch (e: Exception) {
            callBack.onErrorAuthenticate(
                FeatureIdentityException(
                    code = ErrorConstant.UNABLE_ENCRYPT_AUTHENTICATE,
                    message = e.message,
                )
            )
        }
    }

    @RequiresApi(Build.VERSION_CODES.P)
    private fun generalAuthenticateBiometricAndroidP(
        callback: BiometricPrompt.AuthenticationCallback,
        negativeButtonCallback: DialogInterface.OnClickListener,
        cryptoObject: CryptoObject?,
        setDeviceCredentialAllowed: Boolean = false,
        setConfirmationRequired: Boolean = false,
        authenticator: Int,
        title: String,
        subTitle: String? = null,
        description: String,
        negativeText: String,
    ) {
        val cancellationSignal = CancellationSignal()
        val executor = ContextCompat.getMainExecutor(context)
        val biometricPrompt = BiometricPrompt.Builder(context)
            .setTitle(title)
            .apply {
                if (!subTitle.isNullOrEmpty()) {
                    setSubtitle(subTitle)
                }
            }
            .setDescription(description)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setAllowedAuthenticators(authenticator)
                }

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    setDeviceCredentialAllowed(setDeviceCredentialAllowed)
                }

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    setConfirmationRequired(setConfirmationRequired)
                }

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    if (!setDeviceCredentialAllowed && authenticator != BiometricManager.Authenticators.DEVICE_CREDENTIAL) {
                        setNegativeButton(negativeText, executor, negativeButtonCallback)
                    }
                }
            }
            .build()

        if (cryptoObject != null) {
            biometricPrompt.authenticate(
                cryptoObject,
                cancellationSignal,
                executor,
                callback
            )
        } else {
            biometricPrompt.authenticate(
                cancellationSignal,
                executor,
                callback
            )
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun generalAuthenticateAndroidM(
        cryptoObject: FingerprintManager.CryptoObject?,
        callback: FingerprintManager.AuthenticationCallback,
    ) {
        val cancellationSignal = CancellationSignal()
        val handler = Handler(Looper.getMainLooper())
        fingerprintManager.authenticate(
            cryptoObject,
            cancellationSignal,
            0,
            callback,
            handler

        )
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
    override fun encrypt(cipher: Cipher, plainText: String): String {
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
    override fun decrypt(cipher: Cipher, encryptedText: ByteArray): String {
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
    override fun decrypt(cipher: Cipher, encryptedText: String): String {
        val decodedText =
            Base64.decode(encryptedText, Base64.NO_WRAP)
        return decrypt(cipher = cipher, encryptedText = decodedText)
    }
}