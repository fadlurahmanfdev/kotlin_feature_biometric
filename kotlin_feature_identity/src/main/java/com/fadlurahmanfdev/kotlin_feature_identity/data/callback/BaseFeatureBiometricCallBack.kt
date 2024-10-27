package com.fadlurahmanfdev.kotlin_feature_identity.data.callback

import android.content.DialogInterface
import com.fadlurahmanfdev.kotlin_feature_identity.data.exception.FeatureBiometricException
import javax.crypto.Cipher

interface BaseFeatureBiometricCallBack {
    fun onDialogClick(dialogInterface: DialogInterface?, which: Int) {

    }

    fun onFailedAuthenticate() {}

    fun onErrorAuthenticate(exception: FeatureBiometricException) {}

    fun onCanceled() {}
}

interface FeatureBiometricEncryptSecureCallBack : BaseFeatureBiometricCallBack {
    fun onSuccessAuthenticateEncryptSecureBiometric(cipher: Cipher, encodedIvKey: String)
}

interface FeatureBiometricDecryptSecureCallBack : BaseFeatureBiometricCallBack {
    fun onSuccessAuthenticateDecryptSecureBiometric(cipher: Cipher)
}

interface FeatureBiometricCallBack : BaseFeatureBiometricCallBack {
    fun onSuccessAuthenticate()
}