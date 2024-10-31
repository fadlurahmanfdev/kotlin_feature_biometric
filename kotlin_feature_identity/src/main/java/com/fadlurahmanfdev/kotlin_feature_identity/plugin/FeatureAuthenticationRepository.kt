package com.fadlurahmanfdev.kotlin_feature_identity.plugin

import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.AuthenticationCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.SecureAuthenticationDecryptCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.SecureAuthenticationEncryptCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureAuthenticationStatus
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureAuthenticatorType

interface FeatureAuthenticationRepository {
    fun isDeviceSupportFingerprint(): Boolean
    fun isDeviceSupportFaceAuth(): Boolean
    fun isDeviceSupportBiometric(): Boolean
    fun isFingerprintEnrolled(): Boolean
    fun isDeviceCredentialEnrolled(): Boolean
    fun checkAuthenticatorStatus(authenticatorType: FeatureAuthenticatorType): FeatureAuthenticationStatus
    fun canAuthenticate(authenticatorType: FeatureAuthenticatorType): Boolean
    fun authenticateBiometric(
        title: String,
        subTitle: String?,
        description: String,
        negativeText:String,
        callBack: AuthenticationCallBack
    )

    fun secureAuthenticateBiometricEncrypt(
        alias: String,
        title: String,
        subTitle: String?,
        description: String,
        negativeText:String,
        callBack: SecureAuthenticationEncryptCallBack
    )

    fun secureAuthenticateBiometricDecrypt(
        alias: String,
        encodedIVKey:String,
        title: String,
        subTitle: String?,
        description: String,
        negativeText:String,
        callBack: SecureAuthenticationDecryptCallBack
    )
}