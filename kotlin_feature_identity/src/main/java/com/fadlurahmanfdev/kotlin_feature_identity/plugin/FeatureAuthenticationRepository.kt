package com.fadlurahmanfdev.kotlin_feature_identity.plugin

import android.os.Build
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.kotlin_feature_identity.constant.ErrorConstant
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.AuthenticationCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.SecureAuthenticationDecryptCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.SecureAuthenticationEncryptCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureAuthenticationStatus
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureAuthenticatorType
import com.fadlurahmanfdev.kotlin_feature_identity.data.exception.FeatureIdentityException
import javax.crypto.Cipher

interface FeatureAuthenticationRepository {
    /**
     * Deletes an existing key from the Android KeyStore.
     *
     * @param alias The alias of the entry to delete from the KeyStore. Must not be empty.
     *
     * @throws FeatureIdentityException if unable to delete the key, with error code [ErrorConstant.UNABLE_TO_DELETE_SECRET_KEY].
     */
    fun deleteSecretKey(alias: String)

    /**
     * Checks if the device supports fingerprint authentication.
     *
     * @return true if the device supports fingerprint authentication; false otherwise.
     */
    fun isDeviceSupportFingerprint(): Boolean

    /**
     * Checks if the device supports face authentication.
     *
     * @return true if the device supports face authentication; false otherwise.
     */
    fun isDeviceSupportFaceAuth(): Boolean

    /**
     * Checks if the device supports biometric authentication, either fingerprint or face authentication.
     *
     * @return true if the device supports any biometric feature; false otherwise.
     */
    fun isDeviceSupportBiometric(): Boolean

    /**
     * Checks if the device has at least one fingerprint enrolled.
     *
     * @return true if a fingerprint is enrolled; false otherwise.
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
     * Checks the status of the specified authenticator.
     *
     * @param authenticatorType The type of authenticator (biometric or device credential).
     *
     * @return [FeatureAuthenticationStatus.SUCCESS] if the device can authenticate using the specified authenticator;
     * [FeatureAuthenticationStatus.NONE_ENROLLED] if the device has no enrolled data for the specified authenticator;
     * [FeatureAuthenticationStatus.NO_HARDWARE] if the device lacks the hardware for the specified authenticator;
     * [FeatureAuthenticationStatus.UNAVAILABLE] if the device is currently unable to authenticate with the specified authenticator;
     * [FeatureAuthenticationStatus.SECURITY_UPDATE_REQUIRED] if a security update is required for the device to authenticate;
     * [FeatureAuthenticationStatus.UNSUPPORTED_OS_VERSION] if the OS version does not support authentication;
     * [FeatureAuthenticationStatus.UNKNOWN] if an unknown status is encountered.
     */
    fun checkAuthenticatorStatus(authenticatorType: FeatureAuthenticatorType): FeatureAuthenticationStatus

    /**
     * Checks the status of secure authentication on the device.
     *
     * @return [FeatureAuthenticationStatus.SUCCESS] if the device can authenticate securely;
     * [FeatureAuthenticationStatus.NO_HARDWARE] if the device lacks hardware for secure authentication;
     * [FeatureAuthenticationStatus.UNAVAILABLE] if secure authentication is currently unavailable;
     * [FeatureAuthenticationStatus.SECURITY_UPDATE_REQUIRED] if a security update is required for secure authentication;
     * [FeatureAuthenticationStatus.UNSUPPORTED_OS_VERSION] if the OS version does not support secure authentication;
     * [FeatureAuthenticationStatus.UNKNOWN] if an unknown status is encountered.
     */
    fun checkSecureAuthentication(): FeatureAuthenticationStatus

    /**
     * Determines whether the device can authenticate using the specified authenticator.
     *
     * @param authenticatorType The type of authenticator (biometric or device credential).
     *
     * @return true if the device can authenticate using the specified authenticator; false otherwise.
     */
    fun canAuthenticate(authenticatorType: FeatureAuthenticatorType): Boolean

    /**
     * Authenticate using device credentials.
     *
     * @param title The title displayed in the device credential prompt.
     * @param subTitle The sub-title displayed in the device credential prompt.
     * @param description The description shown in the device credential prompt.
     * @param negativeText The text for the cancel button in the prompt.
     * @param confirmationRequired Whether confirmation is required for authentication.
     * @param callBack The callback to handle the authentication results:
     *
     * - **onSuccessAuthenticate**: Called when the authentication is successful, indicating that
     *   the user has correctly authenticated using their device credentials.
     *
     * - **onFailedAuthenticate**: Called when the authentication fails, usually because the
     *   credentials provided do not match, or due to insufficient attempts. The user may be prompted
     *   to retry or use other authentication methods if available.
     *
     * - **onErrorAuthenticate**: Called when there is an error during authentication, such as
     *   a system-related issue (e.g., the device doesn’t support device credentials, or the user
     *   cannot authenticate). This callback provides an error code and message detailing the
     *   reason for failure, which can be handled appropriately.
     *
     * - **onNegativeButtonClicked**: Called when the user presses the cancel button (negative action),
     *   which dismisses the authentication prompt and halts the authentication process.
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
     * Authenticate using biometric authentication (fingerprint or face).
     *
     * @param title The title displayed in the biometric prompt.
     * @param subTitle The sub-title displayed in the biometric prompt.
     * @param description The description shown in the biometric prompt.
     * @param negativeText The text for the cancel button in the prompt.
     * @param confirmationRequired Whether confirmation is required for authentication.
     * @param callBack The callback to handle the authentication results:
     *
     * - **onSuccessAuthenticate**: Called when biometric authentication is successful, indicating
     *   that the user’s fingerprint or face was recognized. Upon success, further actions may proceed.
     *
     * - **onFailedAuthenticate**: Called when biometric authentication fails, usually due to an
     *   unrecognized fingerprint or face scan. The user can retry authentication.
     *
     * - **onErrorAuthenticate**: Called when an error occurs during authentication, such as system
     *   issues, sensor malfunction, or unsupported OS versions. Provides an error code and message
     *   explaining the error type. For example:
     *   - Error code for OS not supported if the minimum OS version for biometric authentication is not met.
     *   - Error code and message indicating specific sensor issues or interruptions.
     *
     * - **onNegativeButtonClicked**: Called when the user cancels authentication by pressing the
     *   cancel button. The prompt is dismissed, and the authentication process is stopped.
     */
    fun authenticateBiometric(
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: AuthenticationCallBack
    )

    /**
     * Checks if the biometric data on the device has changed.
     *
     * A biometric change is detected if new biometric data (e.g., a fingerprint) has been enrolled on the device.
     * Deleting biometric data is not detected as a change.
     *
     * @param alias The alias of the secret key used to verify biometric integrity.
     *
     * @return true if a biometric change is detected; false otherwise.
     *
     * @throws FeatureIdentityException [ErrorConstant.UNABLE_TO_DETECT_BIOMETRIC_CHANGE] if an error occurs while checking for biometric changes.
     */
    fun isBiometricChanged(alias: String): Boolean

    /**
     * Securely authenticate using biometric encryption.
     *
     * This function performs biometric authentication with encryption, using a specified alias to retrieve or generate
     * a secret key. The encryption is achieved through a cipher initialized with the secret key. If the key becomes invalid
     * (e.g., due to a security change like adding a new fingerprint), the key must be deleted and regenerated.
     *
     * @param alias The alias of the secret key used for encryption. If the key is invalidated, the user must delete it
     *              and generate a new one to continue using secure authentication.
     * @param title The title displayed in the biometric prompt.
     * @param subTitle The sub-title displayed in the biometric prompt.
     * @param description The description shown in the biometric prompt.
     * @param negativeText The text for the cancel button in the prompt.
     * @param confirmationRequired Whether confirmation is required before successful authentication.
     * @param callBack The callback to handle authentication results, including:
     *
     * - **onSuccessAuthenticate**: Called when biometric authentication is successful. This callback provides
     *   the encrypted cipher and IV (Initialization Vector) in Base64 format, allowing further secure operations.
     *
     * - **onFailedAuthenticate**: Called when biometric authentication fails, typically due to unrecognized biometric data.
     *   The user can attempt authentication again if desired.
     *
     * - **onErrorAuthenticate**: Called when an error occurs during authentication. Provides a code and message detailing
     *   the error, such as:
     *   - **Error Constant `KEY_PERMANENTLY_INVALIDATED`**: This occurs if the key has been invalidated. For example, adding
     *     or removing fingerprints will invalidate the key, requiring the user to delete the existing key and generate a
     *     new one with the same alias.
     *   - **Error Constant `CIPHER_MISSING`**: Indicates a missing cipher, which is required for secure authentication.
     *   - **Error Constant `OS_NOT_SUPPORTED`**: Returned when the device OS version does not support the necessary
     *     biometric functionality.
     *   - **General Exception**: If another exception is caught, an error message will indicate the issue (e.g., encryption setup errors).
     *
     * - **onNegativeButtonClicked**: Called when the user presses the cancel button on the biometric prompt, halting the
     *   authentication process.
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
     * Securely authenticate using biometric decryption.
     *
     * This method decrypts data using a biometric-protected secret key. If the key is invalidated
     * (e.g., due to biometric changes like adding a new fingerprint), it cannot be used for decryption.
     * In such cases, users must generate a new key and re-encrypt the data.
     *
     * @param alias The alias of the secret key used for decryption.
     * @param encodedIVKey The IV key obtained from encryption, encoded as a string.
     * @param title The title displayed in the biometric prompt.
     * @param subTitle The sub-title displayed in the biometric prompt.
     * @param description The description shown in the biometric prompt.
     * @param negativeText The text for the cancel button in the prompt.
     * @param confirmationRequired Whether confirmation is required before successful authentication.
     * @param callBack The callback to handle authentication results, including the decrypted cipher.
     *
     * `callBack` provides the following methods:
     * - `onSuccessAuthenticate(cipher: Cipher)`: Called when authentication is successful. The provided
     *   `cipher` can be used to securely decrypt the data using the correct secret key.
     * - `onErrorAuthenticate(exception: FeatureIdentityException)`: Called when an error occurs during
     *   authentication. The exception details the cause of failure, such as:
     *      - `ErrorConstant.SECRET_KEY_MISSING`: The required secret key is missing. Re-encryption
     *        with a new key may be necessary.
     *      - `ErrorConstant.CIPHER_MISSING`: Cipher was not properly initialized for secure decryption.
     *      - `ErrorConstant.KEY_PERMANENTLY_INVALIDATED`: The key is invalidated due to biometric changes
     *        (e.g., new fingerprint added). A new key must be generated to proceed.
     *      - `ErrorConstant.UNABLE_SECURE_AUTHENTICATE`: A generic error, often caused by device or
     *        OS issues.
     * - `onFailedAuthenticate()`: Called when biometric authentication fails but no critical error
     *   occurs. This typically means the user did not authenticate successfully, and they may retry.
     * - `onNegativeButtonClicked(which: Int)`: Called when the user taps the negative button (e.g.,
     *   "Cancel") on the biometric prompt. This cancels the authentication process.
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