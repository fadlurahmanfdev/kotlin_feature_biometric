package com.fadlurahmanfdev.mark_biometric.internal.composition

import android.content.Context
import com.fadlurahmanfdev.mark_biometric.api.MarkAuthenticatorApi
import com.fadlurahmanfdev.mark_biometric.internal.MarkAuthenticatorInternal
import com.fadlurahmanfdev.mark_biometric.internal.dependency.capability.AndroidDeviceCapabilityDataSource
import com.fadlurahmanfdev.mark_biometric.internal.dependency.crypto.AndroidSecretKeyDataSource
import com.fadlurahmanfdev.mark_biometric.internal.dependency.crypto.DefaultCipherDataSource
import com.fadlurahmanfdev.mark_biometric.internal.dependency.encoding.AndroidBase64DataSource
import com.fadlurahmanfdev.mark_biometric.internal.dependency.prompt.AndroidPromptDataSource

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
