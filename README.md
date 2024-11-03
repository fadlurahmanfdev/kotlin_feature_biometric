# Description
Kotlin Feature Identity is a library that handle identity/authentication related, such as biometric, device 
credential, etc.

# Method

## Delete Secret Key

Deletes an existing key from the Android KeyStore.

| Parameter Name   | Type   | Required | Description                                         |
|------------------|--------|----------|-----------------------------------------------------|
| `alias`          | String | yes      | The alias of the entry to delete from the KeyStore. |

## Is Device Support Fingerprint ?

Checks if the device supports fingerprint authentication.

Return true if the device supports fingerprint authentication; false otherwise.

## Is Device Support Face Auth ?

Checks if the device supports face authentication.

Return true if the device supports face authentication; false otherwise.

## Is Device Support Biometric ?

Checks if the device supports biometric authentication, either fingerprint or face authentication.

Return true if the device supports any biometric feature; false otherwise.

## Is Fingerprint Enrolled ?

Checks if the device has at least one fingerprint enrolled.

Return true if a fingerprint is enrolled; false otherwise.

## Is Device Credential Enrolled ?

Determines the device's credential is enrolled (PIN, Password, etc)

Return true, if device's credential already enrolled, otherwise is false.

## Check Authenticator Status

Checks the status of the specified authenticator.

| Parameter Name ,  | Type                     | Required | Description                                                 |
|-------------------|--------------------------|----------|-------------------------------------------------------------|
| authenticatorType | FeatureAuthenticatorType | yes      | The type of authenticator (biometric or device credential). |

Return [FeatureAuthenticationStatus.SUCCESS] if the device can authenticate using the specified authenticator;
[FeatureAuthenticationStatus.NONE_ENROLLED] if the device has no enrolled data for the specified authenticator;
[FeatureAuthenticationStatus.NO_HARDWARE] if the device lacks the hardware for the specified authenticator;
[FeatureAuthenticationStatus.UNAVAILABLE] if the device is currently unable to authenticate with the specified authenticator;
[FeatureAuthenticationStatus.SECURITY_UPDATE_REQUIRED] if a security update is required for the device to authenticate;
[FeatureAuthenticationStatus.UNSUPPORTED_OS_VERSION] if the OS version does not support authentication;
[FeatureAuthenticationStatus.UNKNOWN] if an unknown status is encountered.

## Check Secure Authentication

Checks the status of secure authentication on the device.

Return [FeatureAuthenticationStatus.SUCCESS] if the device can authenticate using the specified authenticator;
[FeatureAuthenticationStatus.NONE_ENROLLED] if the device has no enrolled data for the specified authenticator;
[FeatureAuthenticationStatus.NO_HARDWARE] if the device lacks the hardware for the specified authenticator;
[FeatureAuthenticationStatus.UNAVAILABLE] if the device is currently unable to authenticate with the specified authenticator;
[FeatureAuthenticationStatus.SECURITY_UPDATE_REQUIRED] if a security update is required for the device to authenticate;
[FeatureAuthenticationStatus.UNSUPPORTED_OS_VERSION] if the OS version does not support authentication;
[FeatureAuthenticationStatus.UNKNOWN] if an unknown status is encountered.

## Can Authenticate

Determines whether the device can authenticate using the specified authenticator.

| Parameter Name ,  | Type                     | Required | Description                                                 |
|-------------------|--------------------------|----------|-------------------------------------------------------------|
| authenticatorType | FeatureAuthenticatorType | yes      | The type of authenticator (biometric or device credential). |

Return true if the device can authenticate using the specified authenticator; false otherwise.

## Authenticate using Device Credential

Authenticate using device credentials.

| Parameter Name       | Type                   | Required | Description                                              |
|----------------------|------------------------|----------|----------------------------------------------------------|
| title                | String                 | yes      | The title displayed in the device credential prompt.     |
| subTitle             | String                 | no       | The sub-title displayed in the device credential prompt. |
| description          | String                 | yes      | The description shown in the device credential prompt.   |
| negativeText         | String                 | yes      | The text for the cancel button in the prompt.            |
| confirmationRequired | Boolean                | yes      | Whether confirmation is required for authentication.     |
| callBack             | AuthenticationCallBack | yes      | The callback to handle the authentication.               |

## Authenticate using Biometric

Authenticate using biometric authentication (fingerprint or face).

| Parameter Name       | Type                   | Required | Description                                              |
|----------------------|------------------------|----------|----------------------------------------------------------|
| title                | String                 | yes      | The title displayed in the device credential prompt.     |
| subTitle             | String                 | no       | The sub-title displayed in the device credential prompt. |
| description          | String                 | yes      | The description shown in the device credential prompt.   |
| negativeText         | String                 | yes      | The text for the cancel button in the prompt.            |
| confirmationRequired | Boolean                | yes      | Whether confirmation is required for authentication.     |
| callBack             | AuthenticationCallBack | yes      | The callback to handle the authentication.               |

## Is Biometric Changed ?

Checks if the biometric data on the device has changed.

A biometric change is detected if new biometric data (e.g., a fingerprint) has been enrolled on the device. 
Deleting biometric data is not detected as a change.

| Parameter Name       | Type                   | Required | Description                                                     |
|----------------------|------------------------|----------|-----------------------------------------------------------------|
| alias                | String                 | yes      | The alias of the secret key used to verify biometric integrity. |

## Authenticate Encrypt Biometric

Securely authenticate using biometric encryption.

This function performs biometric authentication with encryption, using a specified alias to retrieve or generate
a secret key. The encryption is achieved through a cipher initialized with the secret key. If the key becomes invalid
(e.g., due to a security change like adding a new fingerprint), the key must be deleted and regenerated.

| Parameter Name       | Type                                | Required | Description                                                                                                                                                         |
|----------------------|-------------------------------------|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| alias                | String                              | yes      | The alias of the secret key used for encryption. If the key is invalidated, the user must delete it and generate a new one to continue using secure authentication. |
| title                | String                              | yes      | The title displayed in the biometric prompt.                                                                                                                        |
| subTitle             | String                              | no       | The description shown in the biometric prompt.                                                                                                                      |
| description          | String                              | yes      | The description shown in the device credential prompt.                                                                                                              |
| negativeText         | String                              | yes      | The text for the cancel button in the prompt.                                                                                                                       |
| confirmationRequired | Boolean                             | yes      | Whether confirmation is required for authentication.                                                                                                                |
| callBack             | SecureAuthenticationEncryptCallBack | yes      | The callback to handle the authentication.                                                                                                                          |


## Authenticate Decrypt Biometric

Securely authenticate using biometric decryption.

This method decrypts data using a biometric-protected secret key. If the key is invalidated
(e.g., due to biometric changes like adding a new fingerprint), it cannot be used for decryption.
In such cases, users must generate a new key and re-encrypt the data.

| Parameter Name         | Type                                | Required | Description                                                                                                                                                         |
|------------------------|-------------------------------------|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| alias                  | String                              | yes      | The alias of the secret key used for encryption. If the key is invalidated, the user must delete it and generate a new one to continue using secure authentication. |
| encodedIVKey           | String                              | yes      | The IV key obtained from encryption, encoded as a string.                                                                                                           |
| title                  | String                              | yes      | The title displayed in the biometric prompt.                                                                                                                        |
| subTitle               | String                              | no       | The description shown in the biometric prompt.                                                                                                                      |
| description            | String                              | yes      | The description shown in the device credential prompt.                                                                                                              |
| negativeText           | String                              | yes      | The text for the cancel button in the prompt.                                                                                                                       |
| confirmationRequired   | Boolean                             | yes      | Whether confirmation is required for authentication.                                                                                                                |
| callBack               | SecureAuthenticationEncryptCallBack | yes      | The callback to handle the authentication.                                                                                                                          |
