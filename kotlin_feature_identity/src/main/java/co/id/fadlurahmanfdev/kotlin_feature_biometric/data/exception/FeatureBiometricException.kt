package co.id.fadlurahmanfdev.kotlin_feature_biometric.data.exception

data class FeatureBiometricException(
    val code: String,
    override val message: String?
) : Throwable(message = message)
