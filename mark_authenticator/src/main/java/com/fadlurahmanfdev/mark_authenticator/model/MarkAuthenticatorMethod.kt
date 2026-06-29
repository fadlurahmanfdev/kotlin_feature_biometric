package com.fadlurahmanfdev.mark_authenticator.model

/**
 * Authentication methods supported by Mark Authenticator.
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
