package com.fadlurahmanfdev.kotlin_feature_identity.data.callback

import com.fadlurahmanfdev.kotlin_feature_identity.data.exception.FeatureIdentityException
import javax.crypto.Cipher

interface BaseFeatureAuthenticationCallBack {
    fun onNegativeButtonClicked() {}
    fun onFailedAuthenticate()

    fun onErrorAuthenticate(exception: FeatureIdentityException)

    fun onCanceled() {}
}

interface AuthenticationCallBack : BaseFeatureAuthenticationCallBack {
    fun onSuccessAuthenticate()
}

interface SecureAuthenticationEncryptCallBack : BaseFeatureAuthenticationCallBack {
    fun onSuccessAuthenticate(cipher: Cipher, encodedIVKey: String)
}

interface SecureAuthenticationDecryptCallBack : BaseFeatureAuthenticationCallBack {
    fun onSuccessAuthenticate(cipher: Cipher)
}