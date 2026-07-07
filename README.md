# Mark Authenticator

Mark Authenticator is an Android Kotlin library for biometric and device-credential authentication.
It also provides secure AES/GCM encryption/decryption helpers backed by Android KeyStore.

## Installation

Add your dependency as usual:

```kotlin
dependencies {
    implementation("com.fadlurahmanfdev:mark_authenticator:<version>")
}
```

## Initialize

```kotlin
val markAuthenticator = MarkAuthenticator(context)
```

## Public API Models

### `MarkAuthenticatorMethod`

- `BIOMETRIC`: weak biometric prompt (fingerprint/face when available)
- `DEVICE_CREDENTIAL`: PIN, pattern, or password prompt

### `MarkAuthenticationStatus`

- `SUCCESS`: method is ready for authentication
- `NO_HARDWARE`: required hardware not available
- `UNAVAILABLE`: hardware is present but temporarily unavailable
- `NONE_ENROLLED`: no credential/biometric has been enrolled
- `SECURITY_UPDATE_REQUIRED`: security update is required by platform
- `UNSUPPORTED_OS_VERSION`: Android API level is too low for operation
- `UNKNOWN`: platform status is not mapped by the library

### `MarkAuthenticatorException`

All errors are exposed as:

```kotlin
data class MarkAuthenticatorException(
    val code: String,
    override val message: String? = null,
    override val cause: Throwable? = null,
)
```

Use `code` for deterministic handling in app logic.

## Feature 1 - Device Capability Checks

Check support and enrollment state before showing a prompt:

```kotlin
val supportFingerprint = markAuthenticator.isDeviceSupportFingerprint()
val supportFace = markAuthenticator.isDeviceSupportFaceAuth()
val supportBiometric = markAuthenticator.isDeviceSupportBiometric()
val biometricEnrolled = markAuthenticator.isBiometricEnrolled()
val credentialEnrolled = markAuthenticator.isDeviceCredentialEnrolled()
```

## Feature 2 - Authenticator Status Checks

Get normalized status for weak biometric, device credential, or secure auth:

```kotlin
val biometricStatus = markAuthenticator.checkAuthenticatorStatus(MarkAuthenticatorMethod.BIOMETRIC)
val credentialStatus = markAuthenticator.checkAuthenticatorStatus(MarkAuthenticatorMethod.DEVICE_CREDENTIAL)
val secureStatus = markAuthenticator.checkSecureAuthentication()
val canUseBiometricNow = markAuthenticator.canAuthenticate(MarkAuthenticatorMethod.BIOMETRIC)
```

## Feature 3 - Weak Biometric Prompt

```kotlin
markAuthenticator.authenticateBiometric(
    activity = this,
    title = "Biometric Authentication",
    subTitle = "Sign In",
    description = "Authenticate using biometric",
    negativeText = "Cancel",
    confirmationRequired = true,
    callback = object : WeakAuthenticationCallback {
        override fun onSuccessAuthenticate() {
            // Authentication success
        }

        override fun onFailedAuthenticate() {
            // Input was not recognized, user can retry
        }

        override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {
            // Fatal prompt/authentication error
        }

        override fun onCanceled() {
            // User canceled prompt
        }
    },
)
```

## Feature 4 - Device Credential Prompt

```kotlin
markAuthenticator.authenticateDeviceCredential(
    activity = this,
    title = "Device Credential Authentication",
    subTitle = "Unlock",
    description = "Authenticate using PIN/pattern/password",
    negativeText = "Cancel",
    confirmationRequired = true,
    callback = object : WeakAuthenticationCallback {
        override fun onSuccessAuthenticate() {}
        override fun onFailedAuthenticate() {}
        override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {}
        override fun onCanceled() {}
    },
)
```

## Feature 5 - Secure Key Management

Generate, read, and delete Android KeyStore keys:

```kotlin
val alias = "sample_alias"

val createdKey = markAuthenticator.generateSecretKey(
    alias = alias,
    invalidatedByBiometricEnrollment = true,
)

val existingKey = markAuthenticator.getSecretKey(alias)

markAuthenticator.deleteSecretKey(alias)
```

## Feature 6 - Secure Encrypt Authentication Flow

Authenticate with strong biometric and get authenticated cipher + IV:

```kotlin
var encryptedText: String? = null
var encodedIv: String? = null

markAuthenticator.secureAuthenticateBiometricEncrypt(
    activity = this,
    alias = "sample_alias",
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

        override fun onFailedAuthenticate() {}

        override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {}

        override fun onCanceled() {}
    },
)
```

## Feature 7 - Secure Decrypt Authentication Flow

Use previously stored encrypted text + IV:

```kotlin
markAuthenticator.secureAuthenticateBiometricDecrypt(
    activity = this,
    alias = "sample_alias",
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

        override fun onFailedAuthenticate() {}

        override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {}

        override fun onCanceled() {}
    },
)
```

## Feature 8 - Direct Encrypt/Decrypt Helpers

For custom flow, you may call crypto helpers directly:

```kotlin
val cipher = markAuthenticator.cipher()
val secretKey = markAuthenticator.getSecretKey("sample_alias") ?: return

cipher.init(Cipher.ENCRYPT_MODE, secretKey)
val encrypted = markAuthenticator.encrypt(cipher, "Hello")
```

```kotlin
val decryptCipher = markAuthenticator.cipher()
// init decryptCipher with your own IV + key first
val plain = markAuthenticator.decrypt(decryptCipher, encrypted)
```

## Feature 9 - Detect Biometric Enrollment Change

Check whether key was invalidated after biometric enrollment changes:

```kotlin
val biometricChanged = markAuthenticator.isBiometricChanged(alias = "sample_alias")
```

## Exception Codes in Library

All codes below are returned in `MarkAuthenticatorException.code`.

- `CIPHER_MISSING`: prompt succeeded but `Cipher` was missing from crypto result
- `UNABLE_FETCH_GET_SECRET_KEY`: failed to read secret key from Android KeyStore
- `SECRET_KEY_MISSING`: decrypt flow requested alias that does not exist
- `UNABLE_SECURE_AUTHENTICATE`: generic secure authentication preparation failure
- `KEY_PERMANENTLY_INVALIDATED`: key became invalid after biometric enrollment change
- `UNABLE_TO_DELETE_SECRET_KEY`: failed to delete key from Android KeyStore
- `UNABLE_TO_DETECT_BIOMETRIC_CHANGE`: unexpected error while checking biometric-change state
- `BAD_PADDING`: decrypt failed because ciphertext/IV/key does not match
- `SECRET_KEY_ALREADY_EXIST`: attempted to create key with alias that already exists

Platform prompt errors may also appear using Android Biometric error code values (as string).

## Example App

The `app` module contains sample usage for all public features in this library.
