package com.fadlurahmanfdev.kotlin_feature_identity.core.exception

data class FeatureIdentityException(
    val code: String,
    override val message: String? = null,
) : Throwable(message = message)