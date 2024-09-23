package com.fadlurahmanfdev.kotlin_feature_identity.data.exception

data class FeatureBiometricException(
    val code: String,
    override val message: String?
) : Throwable(message = message)
