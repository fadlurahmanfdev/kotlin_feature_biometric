package com.fadlurahmanfdev.mark_biometric.internal.dependency.prompt

import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity

internal data class PromptRequest(
    val activity: FragmentActivity,
    val callback: BiometricPrompt.AuthenticationCallback,
    val cryptoObject: BiometricPrompt.CryptoObject?,
    val confirmationRequired: Boolean,
    val authenticator: Int,
    val title: String,
    val subTitle: String?,
    val description: String,
    val negativeText: String,
)
