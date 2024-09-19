package co.id.fadlurahmanfdev.kotlin_feature_biometric.data.callback

import android.content.DialogInterface
import co.id.fadlurahmanfdev.kotlin_feature_biometric.data.exception.FeatureBiometricException
import javax.crypto.Cipher

interface BaseFeatureBiometricCallBack {
    fun onDialogClick(dialogInterface: DialogInterface?, which:Int){

    }

    fun onFailedAuthenticate() {}

    fun onErrorAuthenticate(exception: FeatureBiometricException) {}
}

interface FeatureBiometricSecureCallBack : BaseFeatureBiometricCallBack {

    fun onSuccessAuthenticateEncryptSecureBiometric(cipher: Cipher, encodedIvKey: String) {}
    fun onSuccessAuthenticateDecryptSecureBiometric(cipher: Cipher) {}
}

interface FeatureBiometricCallBack : BaseFeatureBiometricCallBack {
    fun onSuccessAuthenticate() {}
}