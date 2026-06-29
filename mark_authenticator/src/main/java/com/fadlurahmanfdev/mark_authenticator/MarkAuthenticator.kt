package com.fadlurahmanfdev.mark_authenticator

import android.content.Context
import com.fadlurahmanfdev.mark_authenticator.api.MarkAuthenticatorApi
import com.fadlurahmanfdev.mark_authenticator.internal.MarkAuthenticatorInternal

/**
 * Public entry point for Mark Authenticator.
 *
 * This class delegates every call to an internal implementation that is split by layer:
 * `api` (contracts), `model` (public models), `core` (shared constants), and `internal`
 * (Android-specific implementation).
 */
class MarkAuthenticator(context: Context) : MarkAuthenticatorApi by MarkAuthenticatorInternal(context)