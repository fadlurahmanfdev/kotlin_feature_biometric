package com.fadlurahmanfdev.kotlin_feature_identity.data.enums

enum class BiometricType {
    /**
     * Represents biometric authentication using fingerprint recognition or face recognition.
     */
    WEAK,

    /**
     * Represents biometric authentication using fingerprint recognition.
     */
    STRONG,

    /**
     * Represents biometric authentication using device credential (PIN, PASSWORD, or PATTERN).
     */
    DEVICE_CREDENTIAL
}