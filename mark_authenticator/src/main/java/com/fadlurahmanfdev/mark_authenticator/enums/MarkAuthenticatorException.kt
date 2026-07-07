package com.fadlurahmanfdev.mark_authenticator.enums

/**
 * Domain exception exposed to consumer applications.
 *
 * @property code machine-readable error code.
 * @property message human-readable error message.
 * @property cause underlying throwable when available.
 */
data class MarkAuthenticatorException(
    val code: String,
    override val message: String? = null,
    override val cause: Throwable? = null,
) : Throwable(message = message, cause = cause)
