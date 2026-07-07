package com.fadlurahmanfdev.mark_authenticator.internal

import android.hardware.biometrics.BiometricManager
import android.os.Build
import androidx.biometric.BiometricPrompt
import com.fadlurahmanfdev.mark_authenticator.api.callback.SecureAuthenticationDecryptCallback
import com.fadlurahmanfdev.mark_authenticator.api.callback.SecureAuthenticationEncryptCallback
import com.fadlurahmanfdev.mark_authenticator.api.callback.WeakAuthenticationCallback
import com.fadlurahmanfdev.mark_authenticator.core.constant.ErrorConstant
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.Base64DataSource
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.CipherDataSource
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.DeviceCapabilityDataSource
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.PromptDataSource
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.PromptRequest
import com.fadlurahmanfdev.mark_authenticator.internal.dependency.SecretKeyDataSource
import com.fadlurahmanfdev.mark_authenticator.enums.MarkAuthenticationStatus
import com.fadlurahmanfdev.mark_authenticator.enums.MarkAuthenticatorMethod
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class MarkAuthenticatorInternalTest {

    @Test
    fun `support checks should use capability data source`() {
        val sut = createSut(
            capability = FakeDeviceCapabilityDataSource(
                sdkInt = Build.VERSION_CODES.R,
                features = mutableSetOf(
                    android.content.pm.PackageManager.FEATURE_FINGERPRINT,
                    android.content.pm.PackageManager.FEATURE_FACE,
                ),
            ),
        )

        assertTrue(sut.isDeviceSupportFingerprint())
        assertTrue(sut.isDeviceSupportFaceAuth())
        assertTrue(sut.isDeviceSupportBiometric())
    }

    @Test
    fun `checkAuthenticatorStatus should map platform status for biometric`() {
        val capability = FakeDeviceCapabilityDataSource(
            sdkInt = Build.VERSION_CODES.R,
            canAuthenticateStatus = BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED,
        )
        val sut = createSut(capability = capability)

        val status = sut.checkAuthenticatorStatus(MarkAuthenticatorMethod.BIOMETRIC)

        assertEquals(MarkAuthenticationStatus.NONE_ENROLLED, status)
    }

    @Test
    fun `canAuthenticate should return true when status success`() {
        val capability = FakeDeviceCapabilityDataSource(
            sdkInt = Build.VERSION_CODES.R,
            canAuthenticateStatus = BiometricManager.BIOMETRIC_SUCCESS,
        )
        val sut = createSut(capability = capability)

        assertTrue(sut.canAuthenticate(MarkAuthenticatorMethod.BIOMETRIC))
        assertTrue(sut.isBiometricEnrolled())
    }

    @Test
    fun `checkSecureAuthentication should return mapped status`() {
        val capability = FakeDeviceCapabilityDataSource(
            sdkInt = Build.VERSION_CODES.R,
            canAuthenticateStatus = BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED,
        )
        val sut = createSut(capability = capability)

        assertEquals(MarkAuthenticationStatus.SECURITY_UPDATE_REQUIRED, sut.checkSecureAuthentication())
    }

    @Test
    fun `isDeviceCredentialEnrolled should be false below api 23`() {
        val capability = FakeDeviceCapabilityDataSource(
            sdkInt = Build.VERSION_CODES.LOLLIPOP,
            deviceSecure = true,
        )
        val sut = createSut(capability = capability)

        assertFalse(sut.isDeviceCredentialEnrolled())
    }

    @Test
    fun `generate and get secret key should work with fake key store`() {
        val keyStore = FakeSecretKeyDataSource()
        val sut = createSut(secretKeyDataSource = keyStore)

        val generated = sut.generateSecretKey("alias-1", invalidatedByBiometricEnrollment = false)
        val fetched = sut.getSecretKey("alias-1")

        assertNotNull(generated)
        assertEquals(generated, fetched)
    }

    @Test
    fun `deleteSecretKey should remove existing key`() {
        val keyStore = FakeSecretKeyDataSource()
        val sut = createSut(secretKeyDataSource = keyStore)
        sut.generateSecretKey("alias-2", invalidatedByBiometricEnrollment = false)

        sut.deleteSecretKey("alias-2")

        assertEquals(null, sut.getSecretKey("alias-2"))
    }

    @Test
    fun `encrypt and decrypt should roundtrip text`() {
        val sut = createSut()
        val secretKey = generateInMemorySecretKey()
        val plain = "hello-authenticator"

        val encryptCipher = sut.cipher().apply { init(Cipher.ENCRYPT_MODE, secretKey) }
        val encrypted = sut.encrypt(encryptCipher, plain)
        val iv = encryptCipher.iv

        val decryptCipher = sut.cipher().apply {
            init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        }
        val decrypted = sut.decrypt(decryptCipher, encrypted)

        assertEquals(plain, decrypted)

        val decryptCipherFromBytes = sut.cipher().apply {
            init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        }
        val encryptedBytes = Base64.getDecoder().decode(encrypted)
        assertEquals(plain, sut.decrypt(decryptCipherFromBytes, encryptedBytes))
    }

    @Test
    fun `authenticateBiometric should call success callback`() {
        val promptDataSource = FakePromptDataSource(FakePromptDataSource.Mode.SUCCESS)
        val sut = createSut(promptDataSource = promptDataSource)

        val callback = TestWeakCallback()
        sut.authenticateBiometric(
            activity = mockk(relaxed = true),
            title = "title",
            subTitle = "subtitle",
            description = "desc",
            negativeText = "cancel",
            confirmationRequired = true,
            callback = callback,
        )

        assertTrue(callback.successCalled)
    }

    @Test
    fun `authenticateDeviceCredential should call canceled callback for cancel code`() {
        val promptDataSource = FakePromptDataSource(FakePromptDataSource.Mode.CANCELED)
        val sut = createSut(promptDataSource = promptDataSource)
        val callback = TestWeakCallback()

        sut.authenticateDeviceCredential(
            activity = mockk(relaxed = true),
            title = "title",
            subTitle = "subtitle",
            description = "desc",
            negativeText = "cancel",
            confirmationRequired = false,
            callback = callback,
        )

        assertTrue(callback.canceledCalled)
    }

    @Test
    fun `secureAuthenticateBiometricEncrypt should return cipher and iv`() {
        val promptDataSource = FakePromptDataSource(FakePromptDataSource.Mode.SUCCESS)
        val keyStore = FakeSecretKeyDataSource()
        val sut = createSut(
            promptDataSource = promptDataSource,
            secretKeyDataSource = keyStore,
        )
        val callback = TestEncryptCallback()

        sut.secureAuthenticateBiometricEncrypt(
            activity = mockk(relaxed = true),
            alias = "secure-alias",
            title = "title",
            subTitle = "subtitle",
            invalidatedByBiometricEnrollment = false,
            description = "desc",
            negativeText = "cancel",
            confirmationRequired = false,
            callback = callback,
        )

        assertTrue(callback.successCalled)
        assertFalse(callback.encodedIv.isNullOrBlank())
    }

    @Test
    fun `secureAuthenticateBiometricDecrypt should decrypt previously encrypted text`() {
        val promptDataSource = FakePromptDataSource(FakePromptDataSource.Mode.SUCCESS)
        val keyStore = FakeSecretKeyDataSource()
        val sut = createSut(
            promptDataSource = promptDataSource,
            secretKeyDataSource = keyStore,
        )

        val key = sut.generateSecretKey("secure-alias-2", invalidatedByBiometricEnrollment = false)
        val encryptCipher = sut.cipher().apply { init(Cipher.ENCRYPT_MODE, key) }
        val encrypted = sut.encrypt(encryptCipher, "sensitive-data")
        val encodedIv = Base64.getEncoder().encodeToString(encryptCipher.iv)

        val callback = TestDecryptCallback(sut, encrypted)
        sut.secureAuthenticateBiometricDecrypt(
            activity = mockk(relaxed = true),
            alias = "secure-alias-2",
            encodedIVKey = encodedIv,
            title = "title",
            subTitle = null,
            description = "desc",
            negativeText = "cancel",
            confirmationRequired = false,
            callback = callback,
        )

        assertEquals("sensitive-data", callback.decryptedValue)
    }

    @Test
    fun `isBiometricChanged should return false when key missing`() {
        val sut = createSut(secretKeyDataSource = FakeSecretKeyDataSource())
        assertFalse(sut.isBiometricChanged("missing-alias"))
    }

    @Test
    fun `secure decrypt should return SECRET_KEY_MISSING when alias not found`() {
        val sut = createSut()
        val callback = TestDecryptCallback(sut, "ignored")

        try {
            sut.secureAuthenticateBiometricDecrypt(
                activity = mockk(relaxed = true),
                alias = "not-found",
                encodedIVKey = "invalid",
                title = "title",
                subTitle = null,
                description = "desc",
                negativeText = "cancel",
                confirmationRequired = false,
                callback = callback,
            )
        } catch (e: Throwable) {
            assertEquals(ErrorConstant.SECRET_KEY_MISSING, (e as com.fadlurahmanfdev.mark_authenticator.enums.MarkAuthenticatorException).code)
        }
    }

    private fun createSut(
        capability: DeviceCapabilityDataSource = FakeDeviceCapabilityDataSource(),
        secretKeyDataSource: SecretKeyDataSource = FakeSecretKeyDataSource(),
        cipherDataSource: CipherDataSource = FakeCipherDataSource(),
        promptDataSource: PromptDataSource = FakePromptDataSource(FakePromptDataSource.Mode.SUCCESS),
        base64DataSource: Base64DataSource = FakeBase64DataSource(),
    ): MarkAuthenticatorInternal {
        return MarkAuthenticatorInternal(
            capabilityDataSource = capability,
            secretKeyDataSource = secretKeyDataSource,
            cipherDataSource = cipherDataSource,
            promptDataSource = promptDataSource,
            base64DataSource = base64DataSource,
        )
    }

    private fun generateInMemorySecretKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256)
        return keyGenerator.generateKey()
    }
}

private class FakeDeviceCapabilityDataSource(
    override val sdkInt: Int = Build.VERSION_CODES.R,
    private val features: MutableSet<String> = mutableSetOf(),
    private val fingerprintHardwareDetected: Boolean = true,
    private val enrolledFingerprints: Boolean = true,
    private val deviceSecure: Boolean = true,
    private val canAuthenticateStatus: Int? = BiometricManager.BIOMETRIC_SUCCESS,
) : DeviceCapabilityDataSource {
    override fun hasSystemFeature(feature: String): Boolean = features.contains(feature)
    override fun isFingerprintHardwareDetected(): Boolean = fingerprintHardwareDetected
    override fun hasEnrolledFingerprints(): Boolean = enrolledFingerprints
    override fun isDeviceSecure(): Boolean = deviceSecure
    override fun canAuthenticate(authenticator: Int): Int? = canAuthenticateStatus
}

private class FakeSecretKeyDataSource : SecretKeyDataSource {
    private val keys = linkedMapOf<String, SecretKey>()

    override fun getSecretKey(alias: String): SecretKey? = keys[alias]

    override fun generateSecretKey(alias: String, invalidatedByBiometricEnrollment: Boolean): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(256)
        return keyGenerator.generateKey().also { keys[alias] = it }
    }

    override fun deleteSecretKey(alias: String) {
        keys.remove(alias)
    }
}

private class FakeCipherDataSource : CipherDataSource {
    override fun createCipher(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")
}

private class FakeBase64DataSource : Base64DataSource {
    override fun encode(raw: ByteArray): String = Base64.getEncoder().encodeToString(raw)
    override fun decode(encoded: String): ByteArray = Base64.getDecoder().decode(encoded)
}

private class FakePromptDataSource(
    private val mode: Mode,
) : PromptDataSource {
    enum class Mode {
        SUCCESS,
        FAILED,
        CANCELED,
    }

    override fun authenticate(request: PromptRequest) {
        when (mode) {
            Mode.SUCCESS -> {
                val result = mockk<BiometricPrompt.AuthenticationResult>()
                every { result.cryptoObject } returns request.cryptoObject
                request.callback.onAuthenticationSucceeded(result)
            }

            Mode.FAILED -> request.callback.onAuthenticationFailed()
            Mode.CANCELED -> request.callback.onAuthenticationError(
                BiometricPrompt.ERROR_USER_CANCELED,
                "canceled",
            )
        }
    }
}

private class TestWeakCallback : WeakAuthenticationCallback {
    var successCalled = false
    var failedCalled = false
    var canceledCalled = false
    var errorCode: String? = null

    override fun onSuccessAuthenticate() {
        successCalled = true
    }

    override fun onFailedAuthenticate() {
        failedCalled = true
    }

    override fun onErrorAuthenticate(exception: com.fadlurahmanfdev.mark_authenticator.enums.MarkAuthenticatorException) {
        errorCode = exception.code
    }

    override fun onCanceled() {
        canceledCalled = true
    }
}

private class TestEncryptCallback : SecureAuthenticationEncryptCallback {
    var successCalled = false
    var encodedIv: String? = null

    override fun onSuccessAuthenticate(cipher: Cipher, encodedIVKey: String) {
        successCalled = true
        encodedIv = encodedIVKey
    }

    override fun onFailedAuthenticate() = Unit

    override fun onErrorAuthenticate(exception: com.fadlurahmanfdev.mark_authenticator.enums.MarkAuthenticatorException) = Unit
}

private class TestDecryptCallback(
    private val sut: MarkAuthenticatorInternal,
    private val encryptedText: String,
) : SecureAuthenticationDecryptCallback {
    var decryptedValue: String? = null

    override fun onSuccessAuthenticate(cipher: Cipher) {
        decryptedValue = sut.decrypt(cipher, encryptedText)
    }

    override fun onFailedAuthenticate() = Unit

    override fun onErrorAuthenticate(exception: com.fadlurahmanfdev.mark_authenticator.enums.MarkAuthenticatorException) = Unit
}
