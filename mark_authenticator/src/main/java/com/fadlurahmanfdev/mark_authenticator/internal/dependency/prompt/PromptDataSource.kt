package com.fadlurahmanfdev.mark_authenticator.internal.dependency.prompt

internal interface PromptDataSource {
    fun authenticate(request: PromptRequest)
}
