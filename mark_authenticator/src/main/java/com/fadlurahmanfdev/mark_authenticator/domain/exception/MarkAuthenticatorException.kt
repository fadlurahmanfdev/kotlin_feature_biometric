package com.fadlurahmanfdev.mark_authenticator.domain.exception

/**
 * Domain exception exposed to consumer applications.
 *
 * All public APIs return errors by this type so callers can reliably handle failures with
 * [code], while still receiving a readable [message] and optional original [cause].
 *
 * @property code machine-readable error code
 * (for example values from [com.fadlurahmanfdev.mark_authenticator.core.constant.ErrorConstant]).
 * @property message human-readable description from platform or library.
 * @property cause underlying throwable when available.
 */
data class MarkAuthenticatorException(
    val code: String,
    override val message: String? = null,
    override val cause: Throwable? = null,
) : Throwable(message = message, cause = cause)