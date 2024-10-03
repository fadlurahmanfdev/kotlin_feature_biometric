package com.fadlurahmanfdev.kotlin_feature_identity.data.enums

enum class FeatureBiometricStatus {
    /**
     * Can authenticate using biometrics.
     */
    SUCCESS,

    /**
     * No biometric hardware available on the device.
     */
    NO_BIOMETRIC_AVAILABLE,

    /**
     * Biometric hardware is currently unavailable. Please check again later.
     */
    BIOMETRIC_UNAVAILABLE,

    /**
     * No biometric credentials are set up.
     */
    NONE_ENROLLED,
    UNKNOWN,
}