package com.fadlurahmanfdev.mark_biometric.internal.dependency.prompt

import android.content.Context
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricManager as AndroidXBiometricManager
import androidx.core.content.ContextCompat

internal class AndroidPromptDataSource(
    private val context: Context,
) : PromptDataSource {
    override fun authenticate(request: PromptRequest) {
        val executor = ContextCompat.getMainExecutor(context)
        val promptBuilder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(request.title)
            .setDescription(request.description)
            .setAllowedAuthenticators(request.authenticator)
            .setConfirmationRequired(request.confirmationRequired)

        if (!request.subTitle.isNullOrBlank()) {
            promptBuilder.setSubtitle(request.subTitle)
        }

        if (request.authenticator != AndroidXBiometricManager.Authenticators.DEVICE_CREDENTIAL) {
            promptBuilder.setNegativeButtonText(request.negativeText)
        }

        val prompt = BiometricPrompt(request.activity, executor, request.callback)
        val promptInfo = promptBuilder.build()
        if (request.cryptoObject == null) {
            prompt.authenticate(promptInfo)
        } else {
            prompt.authenticate(promptInfo, request.cryptoObject)
        }
    }
}
