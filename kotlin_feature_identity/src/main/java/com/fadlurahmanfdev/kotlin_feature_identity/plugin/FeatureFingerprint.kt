package com.fadlurahmanfdev.kotlin_feature_identity.plugin

import android.content.Context
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import com.fadlurahmanfdev.kotlin_feature_identity.constant.ErrorConstant
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.AuthenticationCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.SecureAuthenticationCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.exception.FeatureIdentityException
import javax.crypto.Cipher

class FeatureFingerprint(private val context: Context) : FeatureFingerprintRepository {

    private lateinit var fingerprintManager: FingerprintManager

    init {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            fingerprintManager =
                context.getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager
        }
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

    override fun isSupportedFingerprint(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return fingerprintManager.isHardwareDetected
        }

        Log.d(this::class.java.simpleName, "OS not supported")
        return false
    }

    override fun isFingerprintEnrolled(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return fingerprintManager.hasEnrolledFingerprints()
        }

        throw FeatureIdentityException(
            code = ErrorConstant.OS_NOT_SUPPORTED,
            message = "OS not supported"
        )
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