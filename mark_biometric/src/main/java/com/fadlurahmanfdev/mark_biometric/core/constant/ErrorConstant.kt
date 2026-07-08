package com.fadlurahmanfdev.mark_biometric.core.constant

/**
 * Error codes returned by [com.fadlurahmanfdev.mark_biometric.domain.exception.MarkAuthenticatorException].
 */
object ErrorConstant {
    /** Authentication succeeded but platform callback did not return cipher. */
    const val CIPHER_MISSING = "CIPHER_MISSING"

    /** Failed to read secret key from Android KeyStore. */
    const val UNABLE_FETCH_GET_SECRET_KEY = "UNABLE_FETCH_GET_SECRET_KEY"

    /** Secret key for requested alias is not found. */
    const val SECRET_KEY_MISSING = "SECRET_KEY_MISSING"

    /** Generic failure while preparing secure biometric flow. */
    const val UNABLE_SECURE_AUTHENTICATE = "UNABLE_SECURE_AUTHENTICATE"

    /** Secret key is invalid because biometric enrollment changed. */
    const val KEY_PERMANENTLY_INVALIDATED = "KEY_PERMANENTLY_INVALIDATED"

    /** Failed to delete secret key from Android KeyStore. */
    const val UNABLE_TO_DELETE_SECRET_KEY = "UNABLE_TO_DELETE_SECRET_KEY"

    /** Failed while checking biometric enrollment changes for key alias. */
    const val UNABLE_TO_DETECT_BIOMETRIC_CHANGE = "UNABLE_TO_DETECT_BIOMETRIC_CHANGE"

    /** Decryption failed because ciphertext or IV does not match. */
    const val BAD_PADDING = "BAD_PADDING"

    /** Key generation failed because alias is already used by existing key. */
    const val SECRET_KEY_ALREADY_EXIST = "SECRET_KEY_ALREADY_EXIST"
}
