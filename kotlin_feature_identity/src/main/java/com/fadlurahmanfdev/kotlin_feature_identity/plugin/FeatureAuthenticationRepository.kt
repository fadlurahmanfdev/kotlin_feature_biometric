package com.fadlurahmanfdev.kotlin_feature_identity.plugin

import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.AuthenticationCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.SecureAuthenticationCallBack

interface FeatureAuthenticationRepository {
    fun isSupportedFingerprint(): Boolean
    fun isFingerprintEnrolled(): Boolean
    fun authenticate(callBack: AuthenticationCallBack)
    fun secureAuthenticate(callBack: SecureAuthenticationCallBack)
}