package com.fadlurahmanfdev.example

import android.os.Build
import android.os.Bundle
import android.widget.TextView
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.recyclerview.widget.RecyclerView
import com.fadlurahmanfdev.example.data.FeatureAction
import com.fadlurahmanfdev.example.data.FeatureModel
import com.fadlurahmanfdev.example.presentation.ListExampleAdapter
import com.fadlurahmanfdev.mark_biometric.api.MarkAuthenticator
import com.fadlurahmanfdev.mark_biometric.api.callback.SecureAuthenticationDecryptCallback
import com.fadlurahmanfdev.mark_biometric.api.callback.SecureAuthenticationEncryptCallback
import com.fadlurahmanfdev.mark_biometric.api.callback.WeakAuthenticationCallback
import com.fadlurahmanfdev.mark_biometric.domain.exception.MarkAuthenticatorException
import com.fadlurahmanfdev.mark_biometric.domain.enums.MarkAuthenticatorMethod
import javax.crypto.Cipher

/**
 * Sample activity used to simulate each supported Mark Biometric flow.
 */
class SelectionFeature : AppCompatActivity(), ListExampleAdapter.Callback {
    private lateinit var markAuthenticator: MarkAuthenticator
    private lateinit var resultTextView: TextView

    private var encryptedText: String? = null
    private var encodedIvKey: String? = null

    private val alias = "sample_mark_biometric_alias"
    private val plainText = "PASSW0RD"

    private val featureItems = listOf(
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            action = FeatureAction.SUPPORT_FINGERPRINT,
            title = "Is Device Support Fingerprint?",
            description = "Checks if fingerprint hardware is available.",
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            action = FeatureAction.SUPPORT_FACE_AUTH,
            title = "Is Device Support Face Authentication?",
            description = "Checks if face authentication hardware is available.",
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            action = FeatureAction.SUPPORT_BIOMETRIC,
            title = "Is Device Support Biometric?",
            description = "Checks if any biometric auth method is available.",
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            action = FeatureAction.BIOMETRIC_ENROLLED,
            title = "Is Any Biometric Enrolled?",
            description = "Checks whether biometric credentials are enrolled.",
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            action = FeatureAction.DEVICE_CREDENTIAL_ENROLLED,
            title = "Is Device Credential Enrolled?",
            description = "Checks PIN/pattern/password enrollment.",
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            action = FeatureAction.BIOMETRIC_STATUS,
            title = "Check Biometric Authenticator Status",
            description = "Returns normalized biometric status.",
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            action = FeatureAction.DEVICE_CREDENTIAL_STATUS,
            title = "Check Device Credential Status",
            description = "Returns normalized device credential status.",
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            action = FeatureAction.PROMPT_BIOMETRIC,
            title = "Prompt Weak Biometric",
            description = "Shows biometric prompt and captures callback result.",
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            action = FeatureAction.PROMPT_DEVICE_CREDENTIAL,
            title = "Prompt Device Credential",
            description = "Shows device credential prompt and captures callback result.",
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            action = FeatureAction.BIOMETRIC_CHANGED,
            title = "Is Biometric Changed?",
            description = "Checks if biometric enrollment invalidated existing key.",
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            action = FeatureAction.DELETE_SECRET_KEY,
            title = "Delete Secret Key",
            description = "Deletes existing secure key for this sample alias.",
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            action = FeatureAction.SECURE_ENCRYPT,
            title = "Secure Encrypt (Strong Biometric)",
            description = "Authenticates and encrypts sample text.",
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            action = FeatureAction.SECURE_DECRYPT,
            title = "Secure Decrypt (Strong Biometric)",
            description = "Authenticates and decrypts previously encrypted text.",
        ),
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_selection_feature)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { view, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        markAuthenticator = MarkAuthenticator(this)
        resultTextView = findViewById(R.id.tvResult)

        val recyclerView = findViewById<RecyclerView>(R.id.rv)
        recyclerView.setHasFixedSize(true)
        recyclerView.setItemViewCacheSize(featureItems.size)

        val adapter = ListExampleAdapter()
        adapter.setCallback(this)
        adapter.setList(featureItems)
        recyclerView.adapter = adapter

        showResult("Tap any item below to simulate a library flow.")
    }

    override fun onClicked(item: FeatureModel) {
        when (item.action) {
            FeatureAction.SUPPORT_FINGERPRINT -> {
                showResult("Fingerprint support: ${markAuthenticator.isDeviceSupportFingerprint()}")
            }

            FeatureAction.SUPPORT_FACE_AUTH -> {
                showResult("Face auth support: ${markAuthenticator.isDeviceSupportFaceAuth()}")
            }

            FeatureAction.SUPPORT_BIOMETRIC -> {
                showResult("Biometric support: ${markAuthenticator.isDeviceSupportBiometric()}")
            }

            FeatureAction.BIOMETRIC_ENROLLED -> {
                showResult("Biometric enrolled: ${markAuthenticator.isBiometricEnrolled()}")
            }

            FeatureAction.DEVICE_CREDENTIAL_ENROLLED -> {
                showResult("Device credential enrolled: ${markAuthenticator.isDeviceCredentialEnrolled()}")
            }

            FeatureAction.BIOMETRIC_STATUS -> {
                val status =
                    markAuthenticator.checkAuthenticatorStatus(MarkAuthenticatorMethod.BIOMETRIC)
                showResult("Biometric status: $status")
            }

            FeatureAction.DEVICE_CREDENTIAL_STATUS -> {
                val status =
                    markAuthenticator.checkAuthenticatorStatus(MarkAuthenticatorMethod.DEVICE_CREDENTIAL)
                showResult("Device credential status: $status")
            }

            FeatureAction.PROMPT_BIOMETRIC -> {
                markAuthenticator.authenticateBiometric(
                    activity = this,
                    title = "Weak Biometric Authentication",
                    subTitle = "Sample Demo",
                    description = "Authenticate to simulate weak biometric flow.",
                    negativeText = "Cancel",
                    confirmationRequired = true,
                    callback = object : WeakAuthenticationCallback {
                        override fun onSuccessAuthenticate() {
                            showResult("Weak biometric authentication succeeded.")
                        }

                        override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {
                            showResult("Weak biometric error: ${exception.code} (${exception.message})")
                        }

                        override fun onFailedAuthenticate() {
                            showResult("Weak biometric failed. Try again.")
                        }

                        override fun onCanceled() {
                            showResult("Weak biometric canceled by user.")
                        }
                    },
                )
            }

            FeatureAction.PROMPT_DEVICE_CREDENTIAL -> {
                markAuthenticator.authenticateDeviceCredential(
                    activity = this,
                    title = "Device Credential Authentication",
                    subTitle = "Sample Demo",
                    description = "Authenticate to simulate device credential flow.",
                    negativeText = "Cancel",
                    confirmationRequired = true,
                    callback = object : WeakAuthenticationCallback {
                        override fun onSuccessAuthenticate() {
                            showResult("Device credential authentication succeeded.")
                        }

                        override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {
                            showResult("Device credential error: ${exception.code} (${exception.message})")
                        }

                        override fun onFailedAuthenticate() {
                            showResult("Device credential failed. Try again.")
                        }

                        override fun onCanceled() {
                            showResult("Device credential canceled by user.")
                        }
                    },
                )
            }

            FeatureAction.BIOMETRIC_CHANGED -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    showResult("Biometric changed: ${markAuthenticator.isBiometricChanged(alias)}")
                } else {
                    showResult("Device not supported to check biometric changed")
                }
            }

            FeatureAction.DELETE_SECRET_KEY -> {
                markAuthenticator.deleteSecretKey(alias)
                encryptedText = null
                encodedIvKey = null
                showResult("Secret key deleted. Encryption state reset.")
            }

            FeatureAction.SECURE_ENCRYPT -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    markAuthenticator.secureAuthenticateBiometricEncrypt(
                        activity = this,
                        alias = alias,
                        title = "Secure Encrypt",
                        subTitle = "Strong Biometric",
                        invalidatedByBiometricEnrollment = true,
                        description = "Authenticate to encrypt sample text.",
                        negativeText = "Cancel",
                        confirmationRequired = false,
                        callback = object : SecureAuthenticationEncryptCallback {
                            override fun onSuccessAuthenticate(
                                cipher: Cipher,
                                encodedIVKey: String
                            ) {
                                encryptedText = markAuthenticator.encrypt(cipher, plainText)
                                encodedIvKey = encodedIVKey
                                showResult(
                                    "Encryption success.\n" +
                                            "Encrypted: $encryptedText\n" +
                                            "Encoded IV: $encodedIvKey",
                                )
                            }

                            override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {
                                showResult("Secure encrypt error: ${exception.code} (${exception.message})")
                            }

                            override fun onFailedAuthenticate() {
                                showResult("Secure encrypt failed. Try again.")
                            }

                            override fun onCanceled() {
                                showResult("Secure encrypt canceled by user.")
                            }
                        },
                    )
                } else {
                    showResult("Device not supported to perform encrypt authentication")
                }
            }

            FeatureAction.SECURE_DECRYPT -> {
                val localEncryptedText = encryptedText
                val localIv = encodedIvKey
                if (localEncryptedText.isNullOrBlank() || localIv.isNullOrBlank()) {
                    showResult("No encrypted payload found. Run Secure Encrypt first.")
                    return
                }

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    markAuthenticator.secureAuthenticateBiometricDecrypt(
                        activity = this,
                        alias = alias,
                        encodedIVKey = localIv,
                        title = "Secure Decrypt",
                        subTitle = "Strong Biometric",
                        description = "Authenticate to decrypt sample text.",
                        negativeText = "Cancel",
                        confirmationRequired = false,
                        callback = object : SecureAuthenticationDecryptCallback {
                            override fun onSuccessAuthenticate(cipher: Cipher) {
                                val decrypted =
                                    markAuthenticator.decrypt(cipher, localEncryptedText)
                                showResult("Decryption success. Plain text: $decrypted")
                            }

                            override fun onErrorAuthenticate(exception: MarkAuthenticatorException) {
                                showResult("Secure decrypt error: ${exception.code} (${exception.message})")
                            }

                            override fun onFailedAuthenticate() {
                                showResult("Secure decrypt failed. Try again.")
                            }

                            override fun onCanceled() {
                                showResult("Secure decrypt canceled by user.")
                            }
                        },
                    )
                } else {
                    showResult("Device not supported to perform decrypt authentication")
                }
            }
        }
    }

    private fun showResult(message: String) {
        resultTextView.text = message
    }
}
