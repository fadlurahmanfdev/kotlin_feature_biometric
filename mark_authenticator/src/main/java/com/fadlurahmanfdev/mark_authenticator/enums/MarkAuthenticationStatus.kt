package com.fadlurahmanfdev.mark_authenticator.enums

/**
 * Normalized authentication capability states.
 */
enum class MarkAuthenticationStatus {
    /**
     * Authentication can be performed.
     */
    SUCCESS,

    /**
     * Required hardware is not available on the device.
     */
    NO_HARDWARE,

    /**
     * Hardware exists but is temporarily unavailable.
     */
    UNAVAILABLE,

    /**
     * Hardware exists but no credential/biometric is enrolled.
     */
    NONE_ENROLLED,

    /**
     * Security patch/update is required before authentication is allowed.
     */
    SECURITY_UPDATE_REQUIRED,

    /**
     * Current OS/API level does not support this operation.
     */
    UNSUPPORTED_OS_VERSION,

    /**
     * Unknown or unmapped platform status.
     */
    UNKNOWN,
}
