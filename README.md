# Mark Authenticator

Mark Authenticator is an Android Kotlin library for biometric and device-credential authentication.
It supports runtime capability checks, authentication prompt flows, and secure encryption/decryption
with Android KeyStore-backed keys.

## Requirements

- `minSdk`: 21
- AndroidX Biometric (managed by this library)

## Quick Start

```kotlin
val markAuthenticator = MarkAuthenticator(context)
```

## Public API Models

### `MarkAuthenticatorMethod`

- `BIOMETRIC`: Weak biometric capability/authentication.
- `DEVICE_CREDENTIAL`: PIN, pattern, or password.

### `MarkAuthenticationStatus`

- `SUCCESS`
- `NO_HARDWARE`
- `UNAVAILABLE`
- `NONE_ENROLLED`
- `SECURITY_UPDATE_REQUIRED`
- `UNSUPPORTED_OS_VERSION`
- `UNKNOWN`

### `MarkAuthenticatorException`

Exception returned by callbacks and secure flow helpers.

- `code: String` - machine-readable error code
- `message: String?` - human-readable message
- `cause: Throwable?` - original cause

## Capability Checks

```kotlin
val isSupportFingerprint = markAuthenticator.isDeviceSupportFingerprint()
val isSupportFaceAuth = markAuthenticator.isDeviceSupportFaceAuth()
val isSupportBiometric = markAuthenticator.isDeviceSupportBiometric()
val isBiometricEnrolled = markAuthenticator.isBiometricEnrolled()
val isDeviceCredentialEnrolled = markAuthenticator.isDeviceCredentialEnrolled()
```

## Authenticator Status

```kotlin
val biometricStatus = markAuthenticator.checkAuthenticatorStatus(MarkAuthenticatorMethod.BIOMETRIC)
val deviceCredentialStatus = markAuthenticator.checkAuthenticatorStatus(
    MarkAuthenticatorMethod.DEVICE_CREDENTIAL
)
val secureStatus = markAuthenticator.checkSecureAuthentication()
val canAuthenticateBiometric = markAuthenticator.canAuthenticate(MarkAuthenticatorMethod.BIOMETRIC)
```

## Weak Biometric Prompt

```kotlin
markAuthenticator.authenticateBiometric(
    activity = this,
    title = "Biometric Authentication",
    subTitle = "Example",
    description = "Authenticate using biometric",
    negativeText = "Cancel",
    confirmationRequired = true,
    callback = object : WeakAuthenticationCallback {
        override fun onSuccessAuthenticate() {
            // success
        }

        override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {
            // error
        }

        override fun onFailedAuthenticate() {
            // failed
        }

        override fun onCanceled() {
            // canceled
        }
    }
)
```

## Device Credential Prompt

```kotlin
markAuthenticator.authenticateDeviceCredential(
    activity = this,
    title = "Device Credential Authentication",
    subTitle = "Example",
    description = "Authenticate using device credential",
    negativeText = "Cancel",
    confirmationRequired = true,
    callback = object : WeakAuthenticationCallback {
        override fun onSuccessAuthenticate() {}
        override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {}
        override fun onFailedAuthenticate() {}
        override fun onCanceled() {}
    }
)
```

## Secure Encrypt / Decrypt Flow

```kotlin
val alias = "sample_alias"
var encryptedText: String? = null
var encodedIv: String? = null

markAuthenticator.secureAuthenticateBiometricEncrypt(
    activity = this,
    alias = alias,
    title = "Secure Encrypt",
    subTitle = "Strong Biometric",
    invalidatedByBiometricEnrollment = true,
    description = "Authenticate and encrypt data",
    negativeText = "Cancel",
    confirmationRequired = false,
    callback = object : SecureAuthenticationEncryptCallback {
        override fun onSuccessAuthenticate(cipher: Cipher, encodedIVKey: String) {
            encryptedText = markAuthenticator.encrypt(cipher, "PASSW0RD")
            encodedIv = encodedIVKey
        }

        override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {}
        override fun onFailedAuthenticate() {}
    }
)

// Later, decrypt using the stored encrypted text + IV.
markAuthenticator.secureAuthenticateBiometricDecrypt(
    activity = this,
    alias = alias,
    encodedIVKey = encodedIv ?: return,
    title = "Secure Decrypt",
    subTitle = "Strong Biometric",
    description = "Authenticate and decrypt data",
    negativeText = "Cancel",
    confirmationRequired = false,
    callback = object : SecureAuthenticationDecryptCallback {
        override fun onSuccessAuthenticate(cipher: Cipher) {
            val plainText = markAuthenticator.decrypt(cipher, encryptedText ?: return)
        }

        override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {}
        override fun onFailedAuthenticate() {}
    }
)
```

## Key Utilities

```kotlin
val key = markAuthenticator.getSecretKey(alias = "sample_alias")
val generated = markAuthenticator.generateSecretKey(alias = "sample_alias")
markAuthenticator.deleteSecretKey(alias = "sample_alias")
val isBiometricChanged = markAuthenticator.isBiometricChanged(alias = "sample_alias")
```