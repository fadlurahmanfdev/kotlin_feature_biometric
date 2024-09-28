package com.fadlurahmanfdev.example

import android.os.Bundle
import android.os.CancellationSignal
import android.util.Base64
import android.util.Log
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.recyclerview.widget.RecyclerView
import com.fadlurahmanfdev.example.data.FeatureModel
import com.fadlurahmanfdev.example.presentation.ListExampleAdapter
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.FeatureBiometricCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.FeatureBiometricDecryptSecureCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.FeatureBiometricEncryptSecureCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.BiometricType
import com.fadlurahmanfdev.kotlin_feature_identity.data.exception.FeatureBiometricException
import com.fadlurahmanfdev.kotlin_feature_identity.plugin.KotlinFeatureBiometric
import javax.crypto.Cipher

class MainActivity : AppCompatActivity(), ListExampleAdapter.Callback {
    lateinit var featureBiometric: KotlinFeatureBiometric

    private val features: List<FeatureModel> = listOf<FeatureModel>(
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Have Biometric?",
            desc = "Have Biometric?",
            enum = "HAVE_BIOMETRIC"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Can Authenticate",
            desc = "Can Authenticate",
            enum = "CAN_AUTHENTICATE"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Prompt Weak Biometric",
            desc = "Prompt Weak Biometric (Fingerprint & Face Recognition)",
            enum = "PROMPT_WEAK_BIOMETRIC"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Prompt Strong Biometric",
            desc = "Prompt Strong Biometric (Fingerprint)",
            enum = "PROMPT_STRONG_BIOMETRIC"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Prompt Credential Biometric",
            desc = "Prompt Credential Biometric (Device Password)",
            enum = "PROMPT_CREDENTIAL_BIOMETRIC"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Prompt Biometric",
            desc = "Prompt Encrypt Secure Biometric",
            enum = "PROMPT_ENCRYPT_SECURE_BIOMETRIC"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Prompt Decrypt Biometric",
            desc = "Prompt Decrypt Secure Biometric",
            enum = "PROMPT_DECRYPT_SECURE_BIOMETRIC"
        ),
    )

    private lateinit var rv: RecyclerView

    private lateinit var adapter: ListExampleAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }
        rv = findViewById<RecyclerView>(R.id.rv)

        rv.setItemViewCacheSize(features.size)
        rv.setHasFixedSize(true)

        adapter = ListExampleAdapter()
        adapter.setCallback(this)
        adapter.setList(features)
        adapter.setHasStableIds(true)
        rv.adapter = adapter

        featureBiometric = KotlinFeatureBiometric(this)
    }

    private lateinit var cancellationSignal: CancellationSignal
    private val plainText = "PASSW0RD"
    private lateinit var encodedEncryptedPassword: String
    private lateinit var encodedIvKey: String

    override fun onClicked(item: FeatureModel) {
        when (item.enum) {
            "HAVE_BIOMETRIC" -> {
                val isHaveFeatureBiometric = featureBiometric.haveFeatureBiometric()
                Log.d(this::class.java.simpleName, "Device is have feature biometric: $isHaveFeatureBiometric")
            }

            "CAN_AUTHENTICATE" -> {
                featureBiometric.canAuthenticate()
            }

            "PROMPT_WEAK_BIOMETRIC" -> {
                cancellationSignal = CancellationSignal()
                featureBiometric.authenticate(
                    title = "Encrypt Biometric",
                    description = "Authenticate using your biometric",
                    negativeText = "Cancel",
                    cancellationSignal = cancellationSignal,
                    type = BiometricType.WEAK,
                    callBack = object : FeatureBiometricCallBack {
                        override fun onSuccessAuthenticate() {
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Successfully Authenticate ${BiometricType.WEAK}",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }
                    }
                )
            }

            "PROMPT_STRONG_BIOMETRIC" -> {
                cancellationSignal = CancellationSignal()
                featureBiometric.authenticate(
                    title = "Encrypt Biometric",
                    description = "Authenticate using your fingerprint",
                    negativeText = "Cancel",
                    cancellationSignal = cancellationSignal,
                    type = BiometricType.STRONG,
                    callBack = object : FeatureBiometricCallBack {
                        override fun onSuccessAuthenticate() {
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Successfully Authenticate ${BiometricType.STRONG}",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }
                    }
                )
            }

            "PROMPT_CREDENTIAL_BIOMETRIC" -> {
                cancellationSignal = CancellationSignal()
                featureBiometric.authenticate(
                    title = "Encrypt Biometric",
                    description = "Authenticate using your credential",
                    negativeText = "Cancel",
                    cancellationSignal = cancellationSignal,
                    type = BiometricType.DEVICE_CREDENTIAL,
                    callBack = object : FeatureBiometricCallBack {
                        override fun onSuccessAuthenticate() {
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Successfully Authenticate ${BiometricType.DEVICE_CREDENTIAL}",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }
                    }
                )
            }

            "PROMPT_ENCRYPT_SECURE_BIOMETRIC" -> {
                cancellationSignal = CancellationSignal()
                featureBiometric.authenticateSecureEncrypt(
                    title = "Encrypt Biometric",
                    description = "This will encrypt your text into encrypted text",
                    negativeText = "Cancel",
                    alias = "fadlurahmanfdev",
                    cancellationSignal = cancellationSignal,
                    callBack = object : FeatureBiometricEncryptSecureCallBack {
                        override fun onSuccessAuthenticateEncryptSecureBiometric(
                            cipher: Cipher,
                            encodedIvKey: String
                        ) {
                            encodedEncryptedPassword = featureBiometric.encrypt(cipher, plainText)
                            this@MainActivity.encodedIvKey = encodedIvKey
                            Log.d(
                                this@MainActivity::class.java.simpleName,
                                "ENCODED IV KEY: ${this@MainActivity.encodedIvKey}"
                            )
                            Log.d(
                                this@MainActivity::class.java.simpleName,
                                "ENCODED ENCRYPTED PASSWORD: $encodedEncryptedPassword"
                            )
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Successfully Encrypt",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }
                    }
                )
            }

            "PROMPT_DECRYPT_SECURE_BIOMETRIC" -> {
                encodedIvKey = "P4iutD98cgrNRYI9tFFACw=="
                encodedEncryptedPassword = "42PRlUASXGODBWUa0je10w=="
                cancellationSignal = CancellationSignal()
                featureBiometric.authenticateSecureDecrypt(
                    alias = "fadlurahmanfdev",
                    encodedIvKey = encodedIvKey,
                    title = "Decrypt Biometric",
                    description = "This will decrypt your text into plain text",
                    negativeText = "Cancel",
                    cancellationSignal = cancellationSignal,
                    callBack = object : FeatureBiometricDecryptSecureCallBack {
                        override fun onSuccessAuthenticateDecryptSecureBiometric(cipher: Cipher) {
                            val decodedPassword =
                                Base64.decode(encodedEncryptedPassword, Base64.NO_WRAP)
                            val plainPassword = featureBiometric.decrypt(cipher, decodedPassword)
                            Log.d(
                                this@MainActivity::class.java.simpleName,
                                "DECRYPTED PASSWORD: $plainPassword"
                            )
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Successfully Decrypt",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }

                        override fun onErrorAuthenticate(exception: FeatureBiometricException) {
                            super.onErrorAuthenticate(exception)
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Error Authentication: ${exception.code}",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }
                    }
                )
            }
        }
    }
}