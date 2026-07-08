package com.fadlurahmanfdev.mark_biometric.internal.dependency.prompt

internal interface PromptDataSource {
    fun authenticate(request: PromptRequest)
}
