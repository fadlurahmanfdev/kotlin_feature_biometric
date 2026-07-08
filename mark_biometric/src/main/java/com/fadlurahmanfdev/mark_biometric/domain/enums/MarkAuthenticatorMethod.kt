package com.fadlurahmanfdev.mark_biometric.domain.enums

/**
 * Authentication methods supported by Mark Biometric.
 */
enum class MarkAuthenticatorMethod {
    /**
     * Weak biometric authentication (fingerprint, face, and equivalent weak classes).
     */
    BIOMETRIC,

    /**
     * Device credential authentication (PIN, pattern, or password).
     */
    DEVICE_CREDENTIAL,
}
