package com.fadlurahmanfdev.kotlin_feature_identity.plugin

import android.os.Build
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.AuthenticationCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.SecureAuthenticationDecryptCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.SecureAuthenticationEncryptCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureAuthenticationStatus
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureAuthenticatorType
import com.fadlurahmanfdev.kotlin_feature_identity.data.exception.FeatureIdentityException
import javax.crypto.Cipher

interface FeatureAuthenticationRepository {
    /**
     * Delete the existing key
     *
     * @param alias alias of the entry in which the generated key will appear in Android KeyStore. Must not be empty.
     */
    fun deleteSecretKey(alias: String)

    /**
     * Determines the device's support fingerprint.
     *
     * @return true, if device support biometric, otherwise is false.
     */
    fun isDeviceSupportFingerprint(): Boolean

    /**
     * Determines the device's support face authentication.
     *
     * @return true, if device support face authentication, otherwise is false.
     */
    fun isDeviceSupportFaceAuth(): Boolean

    /**
     * Determines the device's support biometric feature, either fingerprint or face authentication.
     *
     * @return true, if device support biometric, otherwise is false.
     */
    fun isDeviceSupportBiometric(): Boolean

    /**
     * Determines the device's already enrolled with fingerprint
     *
     * @return true, if device already enrolled, otherwise is false.
     */
    @RequiresApi(Build.VERSION_CODES.M)
    fun isFingerprintEnrolled(): Boolean

    /**
     * Determines the device's credential is enrolled (PIN, Password, etc)
     *
     * @return true, if device's credential already enrolled, otherwise is false.
     */
    @RequiresApi(Build.VERSION_CODES.M)
    fun isDeviceCredentialEnrolled(): Boolean

    /**
     * Determines the status of the authenticator
     *
     * @param authenticatorType type of authenticator (biometric or device credential)
     *
     * @return [FeatureAuthenticationStatus]
     */
    fun checkAuthenticatorStatus(authenticatorType: FeatureAuthenticatorType): FeatureAuthenticationStatus

    /**
     * Determines the status of the secure authentication
     *
     * @return [FeatureAuthenticationStatus]
     */
    fun checkSecureAuthentication(): FeatureAuthenticationStatus

    /**
     * Determines whether device can authenticate using specific authenticator
     *
     * @param authenticatorType type of authenticator (biometric or device credential)
     *
     * @return true if device can authenticate, otherwise is false
     */
    fun canAuthenticate(authenticatorType: FeatureAuthenticatorType): Boolean

    /**
     * Authenticate using device credential
     *
     * @param title the title will be shown in prompt device credential
     * @param subTitle the sub-title will be shown in prompt device credential
     * @param description the description will be shown in prompt device credential
     * @param negativeText the canceled button text will be shown to user
     * @param callBack the callback of authenticate result
     *
     */
    @RequiresApi(Build.VERSION_CODES.R)
    fun authenticateDeviceCredential(
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: AuthenticationCallBack,
    )

    /**
     * Authenticate using device biometric.
     *
     * @param title the title will be shown in prompt device credential
     * @param subTitle the sub-title will be shown in prompt device credential
     * @param description the description will be shown in prompt device credential
     * @param negativeText the canceled button text will be shown to user
     * @param callBack the callback of authenticate result
     *
     */
    fun authenticateBiometric(
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: AuthenticationCallBack
    )

    fun isBiometricChanged(alias: String): Boolean

    /**
     * Secure authenticate using encrypt biometric
     *
     * @param alias the alias of the secret key
     * @param title the title will be shown in prompt device credential
     * @param subTitle the sub-title will be shown in prompt device credential
     * @param description the description will be shown in prompt device credential
     * @param negativeText the canceled button text will be shown to user
     * @param confirmationRequired if true, user will be asked by confirmation before success authenticate
     * @param callBack the callback of authenticate result
     *
     */
    fun secureAuthenticateBiometricEncrypt(
        alias: String,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: SecureAuthenticationEncryptCallBack
    )

    /**
     * Secure authenticate using encrypt biometric
     *
     * @param alias the alias of the secret key
     * @param encodedIVKey the IV Key get from encrypt
     * @param title the title will be shown in prompt device credential
     * @param subTitle the sub-title will be shown in prompt device credential
     * @param description the description will be shown in prompt device credential
     * @param negativeText the canceled button text will be shown to user
     * @param confirmationRequired if true, user will be asked by confirmation before success authenticate
     * @param callBack the callback of authenticate result
     *
     */
    fun secureAuthenticateBiometricDecrypt(
        alias: String,
        encodedIVKey: String,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: SecureAuthenticationDecryptCallBack
    )

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
    fun encrypt(cipher: Cipher, plainText: String): String

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
     * @throws FeatureIdentityException If the decryption fails due to padding issues (BadPaddingException).
     */
    fun decrypt(cipher: Cipher, encryptedText: ByteArray): String

    /**
     * Decrypts an encrypted text using the provided cipher.
     *
     * This function takes a `Cipher` initialized for decryption and a Base64-encoded encrypted string.
     * It decodes the encrypted string from Base64 to a byte array, and then decrypts it using the
     * `decrypt(cipher, encryptedPassword: ByteArray)` function.
     *
     * @param cipher The `Cipher` instance initialized in `DECRYPT_MODE`.
     * @param encryptedText The Base64-encoded encrypted string to be decrypted.
     * @return The decrypted plain text string.
     * @throws FeatureIdentityException If the decryption fails due to padding issues.
     */
    fun decrypt(cipher: Cipher, encryptedText: String): String
}