package com.fadlurahmanfdev.mark_biometric.api.callback

import com.fadlurahmanfdev.mark_biometric.domain.exception.MarkAuthenticatorException
import javax.crypto.Cipher

/**
 * Base callback for all authentication flows.
 */
interface MarkAuthenticationCallback {
    /**
     * Called when authentication input is provided but does not match.
     */
    fun onFailedAuthenticate()

    /** Called when authentication flow fails with a concrete error code and message. */
    fun onErrorAuthenticate(exception: MarkAuthenticatorException)

    /**
     * Called when user cancels the prompt.
     */
    fun onCanceled() {}
}

/**
 * Callback for weak biometric and device credential authentication.
 */
interface WeakAuthenticationCallback : MarkAuthenticationCallback {
    /**
     * Called when authentication succeeds.
     */
    fun onSuccessAuthenticate()
}

/**
 * Callback for secure biometric auth in encrypt mode.
 */
interface SecureAuthenticationEncryptCallback : MarkAuthenticationCallback {
    /**
     * Called when authentication succeeds with a cipher ready to encrypt.
     *
     * @param cipher authenticated cipher instance.
     * @param encodedIVKey Base64 encoded IV required for decrypt flow.
     */
    fun onSuccessAuthenticate(cipher: Cipher, encodedIVKey: String)
}

/**
 * Callback for secure biometric auth in decrypt mode.
 */
interface SecureAuthenticationDecryptCallback : MarkAuthenticationCallback {
    /**
     * Called when authentication succeeds with a cipher ready to decrypt.
     */
    fun onSuccessAuthenticate(cipher: Cipher)
}
