package com.fadlurahmanfdev.kotlin_feature_identity.data.enums

enum class FeatureAuthenticatorType {
    /**
     * Represents biometric authentication using weak biometric
     */
    BIOMETRIC,

    /**
     * Represents biometric authentication using device credential (PIN, PASSWORD, or PATTERN).
     */
    DEVICE_CREDENTIAL
}