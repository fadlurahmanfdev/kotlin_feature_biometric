package com.fadlurahmanfdev.kotlin_feature_identity.plugin

import android.os.CancellationSignal
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.FeatureBiometricCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.FeatureBiometricDecryptSecureCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.FeatureBiometricEncryptSecureCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureAuthenticatorType
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureAuthenticationStatus

interface KotlinFeatureBiometricRepository {
    fun isDeviceSupportBiometric(): Boolean
    fun isDeviceSupportFaceAuthentication(): Boolean
    fun canAuthenticate(type: FeatureAuthenticatorType): Boolean
    fun checkAuthenticationStatus(type: FeatureAuthenticatorType): FeatureAuthenticationStatus
    fun isBiometricChanged(alias: String): Boolean
    fun generateSecretKey(alias: String)
    fun deleteSecretKey(alias: String)
    fun authenticate(
        type: FeatureAuthenticatorType,
        cancellationSignal: CancellationSignal,
        title: String,
        description: String,
        negativeText: String,
        callBack: FeatureBiometricCallBack,
    )
    fun authenticateSecureEncrypt(
        alias: String,
        title: String,
        description: String,
        negativeText: String,
        cancellationSignal: CancellationSignal,
        callBack: FeatureBiometricEncryptSecureCallBack,
    )
    fun authenticateSecureDecrypt(
        alias: String,
        encodedIvKey: String,
        title: String,
        description: String,
        negativeText: String,
        cancellationSignal: CancellationSignal,
        callBack: FeatureBiometricDecryptSecureCallBack,
    )
}