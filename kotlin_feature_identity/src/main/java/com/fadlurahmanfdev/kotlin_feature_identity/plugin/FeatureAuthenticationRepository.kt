package com.fadlurahmanfdev.kotlin_feature_identity.plugin

import android.content.Intent
import android.os.Build
import androidx.annotation.RequiresApi
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.AuthenticationCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.SecureAuthenticationDecryptCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.SecureAuthenticationEncryptCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureAuthenticationStatus
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureAuthenticatorType

interface FeatureAuthenticationRepository {
    fun isDeviceSupportFingerprint(): Boolean
    fun isDeviceSupportFaceAuth(): Boolean
    fun isDeviceSupportBiometric(): Boolean
    @RequiresApi(Build.VERSION_CODES.M)
    fun isFingerprintEnrolled(): Boolean
    @RequiresApi(Build.VERSION_CODES.M)
    fun isDeviceCredentialEnrolled(): Boolean
    fun checkAuthenticatorStatus(authenticatorType: FeatureAuthenticatorType): FeatureAuthenticationStatus
    fun canAuthenticate(authenticatorType: FeatureAuthenticatorType): Boolean

    fun getIntentAuthenticateDeviceCredential(
        title: String,
        description: String,
    ): Intent

    @RequiresApi(Build.VERSION_CODES.R)
    fun authenticateDeviceCredential(
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: AuthenticationCallBack,
    )

    fun authenticateBiometric(
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: AuthenticationCallBack
    )

    fun secureAuthenticateBiometricEncrypt(
        alias: String,
        title: String,
        subTitle: String?,
        description: String,
        negativeText: String,
        confirmationRequired: Boolean,
        callBack: SecureAuthenticationEncryptCallBack
    )

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
}