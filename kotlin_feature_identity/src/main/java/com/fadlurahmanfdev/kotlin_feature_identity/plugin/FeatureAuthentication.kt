package com.fadlurahmanfdev.kotlin_feature_identity.plugin

import android.content.Context
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import com.fadlurahmanfdev.kotlin_feature_identity.constant.ErrorConstant
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.AuthenticationCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.SecureAuthenticationCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureAuthenticationStatus
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureAuthenticatorType
import com.fadlurahmanfdev.kotlin_feature_identity.data.exception.FeatureIdentityException
import javax.crypto.Cipher

class FeatureAuthentication(private val context: Context) : FeatureAuthenticationRepository {

    private lateinit var fingerprintManager: FingerprintManager
    private lateinit var biometricManager: BiometricManager

    init {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            fingerprintManager =
                context.getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager
        }

        biometricManager = BiometricManager.from(context)
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

    override fun isDeviceSupportFingerprint(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return context.packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT) || fingerprintManager.isHardwareDetected
        }

        return false
    }

    override fun isDeviceSupportFaceAuth(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return context.packageManager.hasSystemFeature(PackageManager.FEATURE_FACE) || context.packageManager.hasSystemFeature(
                "com.samsung.android.bio.face"
            )
        }

        return false
    }

    override fun isDeviceSupportBiometric(): Boolean {
        return (isDeviceSupportFingerprint() || isDeviceSupportFaceAuth())
    }

    override fun checkAuthenticatorStatus(authenticatorType: FeatureAuthenticatorType): FeatureAuthenticationStatus {
        val authenticatorStatus: Int =  when (authenticatorType) {
            FeatureAuthenticatorType.BIOMETRIC -> {
                biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK)
            }

            FeatureAuthenticatorType.DEVICE_CREDENTIAL -> {
                biometricManager.canAuthenticate(BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            }
        }

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

            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED -> {
                FeatureAuthenticationStatus.UNSUPPORTED_OS_VERSION
            }

            else -> {
                FeatureAuthenticationStatus.UNKNOWN
            }
        }
    }

    override fun canAuthenticate(authenticatorType: FeatureAuthenticatorType): Boolean {
        return checkAuthenticatorStatus(authenticatorType) == FeatureAuthenticationStatus.SUCCESS
    }

    override fun authenticate(
        callBack: AuthenticationCallBack
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            authenticate(
                false,
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
        }

        throw FeatureIdentityException(
            code = ErrorConstant.OS_NOT_SUPPORTED,
            message = "OS not supported"
        )
    }

    override fun secureAuthenticate(callBack: SecureAuthenticationCallBack) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            authenticate(
                true,
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

                        val cipher = result.cryptoObject.cipher
                        val encodedIvKey =
                            Base64.encodeToString(cipher.iv, Base64.NO_WRAP)
                        callBack.onSuccessAuthenticate(
                            cipher,
                            encodedIvKey
                        )
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
        }

        throw FeatureIdentityException(
            code = ErrorConstant.OS_NOT_SUPPORTED,
            message = "OS not supported"
        )
    }

    private fun authenticate(
        secureAuthenticate: Boolean = false,
        callback: FingerprintManager.AuthenticationCallback,
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            var cryptoObject: FingerprintManager.CryptoObject? = null
            if (secureAuthenticate) {
                cryptoObject = FingerprintManager.CryptoObject(getCipher())
            }

            val cancellationSignal = CancellationSignal()
            val handler = Handler(Looper.getMainLooper())
            fingerprintManager.authenticate(
                cryptoObject,
                cancellationSignal,
                0,
                callback,
                handler

            )
        } else {
            throw FeatureIdentityException(
                code = ErrorConstant.OS_NOT_SUPPORTED,
                message = "OS not supported"
            )
        }
    }
}