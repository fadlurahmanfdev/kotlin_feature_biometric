package com.fadlurahmanfdev.kotlin_feature_identity.plugin

import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.AuthenticationCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.SecureAuthenticationCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureAuthenticationStatus
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureAuthenticatorType

interface FeatureAuthenticationRepository {
    fun isDeviceSupportFingerprint(): Boolean
    fun isDeviceSupportFaceAuth(): Boolean
    fun isDeviceSupportBiometric(): Boolean
    fun checkAuthenticatorStatus(authenticatorType: FeatureAuthenticatorType): FeatureAuthenticationStatus
    fun canAuthenticate(authenticatorType: FeatureAuthenticatorType): Boolean
    fun authenticate(callBack: AuthenticationCallBack)
    fun secureAuthenticate(callBack: SecureAuthenticationCallBack)
}