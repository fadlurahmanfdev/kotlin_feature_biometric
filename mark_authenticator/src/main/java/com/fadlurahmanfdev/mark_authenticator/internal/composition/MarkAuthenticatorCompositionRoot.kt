package com.fadlurahmanfdev.mark_authenticator.internal.composition

import android.content.Context
import com.fadlurahmanfdev.mark_authenticator.api.MarkAuthenticatorApi
import com.fadlurahmanfdev.mark_authenticator.internal.MarkAuthenticatorInternal
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.capability.AndroidDeviceCapabilityDataSource
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.crypto.AndroidSecretKeyDataSource
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.crypto.DefaultCipherDataSource
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.encoding.AndroidBase64DataSource
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.prompt.AndroidPromptDataSource

internal object MarkAuthenticatorCompositionRoot {
    fun create(context: Context): MarkAuthenticatorApi {
        return MarkAuthenticatorInternal(
            capabilityDataSource = AndroidDeviceCapabilityDataSource(context),
            secretKeyDataSource = AndroidSecretKeyDataSource(),
            cipherDataSource = DefaultCipherDataSource(),
            promptDataSource = AndroidPromptDataSource(context),
            base64DataSource = AndroidBase64DataSource(),
        )
    }
}
