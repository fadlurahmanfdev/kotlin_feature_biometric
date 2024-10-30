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
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.AuthenticatorType
import com.fadlurahmanfdev.kotlin_feature_identity.data.exception.FeatureBiometricException
import com.fadlurahmanfdev.kotlin_feature_identity.plugin.KotlinFeatureBiometric
import javax.crypto.Cipher

class MainActivity : AppCompatActivity(), ListExampleAdapter.Callback {
    lateinit var featureBiometric: KotlinFeatureBiometric

    private val features: List<FeatureModel> = listOf<FeatureModel>(
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Is Device Support Biometric?",
            desc = "Check whether device support biometric",
            enum = "DEVICE_SUPPORT_BIOMETRIC"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Can Authenticate Using Biometric",
            desc = "Check whether device can authenticate using biometric",
            enum = "CAN_AUTHENTICATE_USING_BIOMETRIC"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Can Authenticate Using Device Credential",
            desc = "Check whether device can authenticate using Device Credential",
            enum = "CAN_AUTHENTICATE_USING_DEVICE_CREDENTIAL"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "---------------------------",
            desc = "---------------------------",
            enum = "-"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Prompt Weak Biometric",
            desc = "Prompt Weak Biometric (Fingerprint & Face Recognition)",
            enum = "PROMPT_WEAK_BIOMETRIC"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Prompt Credential Biometric",
            desc = "Prompt Credential Biometric (Device Password)",
            enum = "PROMPT_CREDENTIAL_BIOMETRIC"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "---------------------------",
            desc = "---------------------------",
            enum = "-"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Generate Secret Key",
            desc = "Generate Secret Key",
            enum = "GENERATE_SECRET_KEY"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Is Biometric Changed?",
            desc = "Check whether new fingerprint/biometric added/changed",
            enum = "IS_BIOMETRIC_CHANGED"
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
            "DEVICE_SUPPORT_BIOMETRIC" -> {
                val isDeviceSupportBiometric = featureBiometric.isDeviceSupportBiometric()
                Log.d(
                    this::class.java.simpleName,
                    "is device support biometric: $isDeviceSupportBiometric"
                )
            }

            "CAN_AUTHENTICATE_USING_BIOMETRIC" -> {
                val canAuthenticate =
                    featureBiometric.canAuthenticate(AuthenticatorType.BIOMETRIC)
                Log.d(
                    this::class.java.simpleName,
                    "can authenticate using biometric: $canAuthenticate"
                )
            }

            "CAN_AUTHENTICATE_USING_DEVICE_CREDENTIAL" -> {
                val canAuthenticate =
                    featureBiometric.canAuthenticate(AuthenticatorType.DEVICE_CREDENTIAL)
                Log.d(
                    this::class.java.simpleName,
                    "can authenticate using device credential: $canAuthenticate"
                )
            }

            "PROMPT_WEAK_BIOMETRIC" -> {
                cancellationSignal = CancellationSignal()
                featureBiometric.authenticate(
                    title = "Title - Weak Biometric",
                    description = "Description - Weak Biometric",
                    negativeText = "Cancel",
                    type = AuthenticatorType.BIOMETRIC,
                    cancellationSignal = cancellationSignal,
                    callBack = object : FeatureBiometricCallBack {
                        override fun onSuccessAuthenticate() {
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Successfully Authenticate ${AuthenticatorType.BIOMETRIC}",
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
                    type = AuthenticatorType.DEVICE_CREDENTIAL,
                    cancellationSignal = cancellationSignal,
                    callBack = object : FeatureBiometricCallBack {
                        override fun onSuccessAuthenticate() {
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Successfully Authenticate ${AuthenticatorType.DEVICE_CREDENTIAL}",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }
                    }
                )
            }

            "GENERATE_SECRET_KEY" -> {
                featureBiometric.generateSecretKey("fadlurahmanfdev")
                val toast = Toast.makeText(
                    this@MainActivity,
                    "Successfully generate secret key",
                    Toast.LENGTH_SHORT
                )
                toast.show()
            }

            "IS_BIOMETRIC_CHANGED" -> {
                val isBiometricChanged = featureBiometric.isBiometricChanged("fadlurahmanfdev")
                Log.d(this::class.java.simpleName, "is biometric changed: $isBiometricChanged")
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
                encodedIvKey = "moTbbjZiSzH7GvKkk21/OA=="
                encodedEncryptedPassword = "aYynFWWEJHXNLpNxlUDjWQ=="
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