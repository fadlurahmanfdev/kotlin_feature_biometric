package co.id.fadlurahmanfdev.kotlinfeaturebiometric

import android.content.DialogInterface
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
import co.id.fadlurahmanfdev.kotlin_feature_biometric.data.callback.FeatureBiometricSecureCallBack
import co.id.fadlurahmanfdev.kotlin_feature_biometric.domain.plugin.KotlinFeatureBiometric
import co.id.fadlurahmanfdev.kotlinfeaturebiometric.data.FeatureModel
import co.id.fadlurahmanfdev.kotlinfeaturebiometric.presentation.ListExampleAdapter
import javax.crypto.Cipher

class MainActivity : AppCompatActivity(), ListExampleAdapter.Callback {
    lateinit var featureBiometric: KotlinFeatureBiometric

    private val features: List<FeatureModel> = listOf<FeatureModel>(
//        FeatureModel(
//            featureIcon = R.drawable.baseline_developer_mode_24,
//            title = "Prompt Weak Biometric",
//            desc = "Prompt Weak Biometric (Fingerprint & Face Recognition)",
//            enum = "PROMPT_WEAK_BIOMETRIC"
//        ),
//        FeatureModel(
//            featureIcon = R.drawable.baseline_developer_mode_24,
//            title = "Prompt Strong Biometric",
//            desc = "Prompt Strong Biometric (Fingerprint)",
//            enum = "PROMPT_STRONG_BIOMETRIC"
//        ),
//        FeatureModel(
//            featureIcon = R.drawable.baseline_developer_mode_24,
//            title = "Prompt Credential Biometric",
//            desc = "Prompt Credential Biometric (Device Password)",
//            enum = "PROMPT_CREDENTIAL_BIOMETRIC"
//        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Prompt Biometric",
            desc = "Prompt Encrypt Secure Biometric",
            enum = "PROMPT_ENCRYPT_SECURE_BIOMETRIC"
        ),
//        FeatureModel(
//            featureIcon = R.drawable.baseline_developer_mode_24,
//            title = "Prompt Decrypt Biometric",
//            desc = "Prompt Decrypt Secure Biometric",
//            enum = "PROMPT_DECRYPT_SECURE_BIOMETRIC"
//        ),
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
//            "PROMPT_WEAK_BIOMETRIC" -> {
//                corePlatformBiometricManager.prompt(
//                    activity = this,
//                    type = BiometricType.WEAK,
//                    title = "Authenticate Biometric",
//                    description = "Authenticate Biometric",
//                    negativeText = "Cancel",
//                    callBack = object : BiometricCallBack {
//                        override fun onSuccessAuthenticate() {
//                            super.onSuccessAuthenticate()
//                            println("SUCCESS AUTHENTICATE")
//                        }
//                    }
//                )
//            }
//
//            "PROMPT_STRONG_BIOMETRIC" -> {
//                corePlatformBiometricManager.prompt(
//                    activity = this,
//                    type = BiometricType.STRONG,
//                    title = "Authenticate Biometric",
//                    description = "Authenticate Biometric",
//                    negativeText = "Cancel",
//                    callBack = object : BiometricCallBack {
//                        override fun onSuccessAuthenticate() {
//                            super.onSuccessAuthenticate()
//                            println("SUCCESS AUTHENTICATE")
//                        }
//                    }
//                )
//            }
//
//            "PROMPT_CREDENTIAL_BIOMETRIC" -> {
//                corePlatformBiometricManager.prompt(
//                    activity = this,
//                    type = BiometricType.DEVICE_CREDENTIAL,
//                    title = "Authenticate Biometric",
//                    description = "Authenticate Biometric",
//                    negativeText = "Cancel",
//                    callBack = object : BiometricCallBack {
//                        override fun onSuccessAuthenticate() {
//                            super.onSuccessAuthenticate()
//                            println("SUCCESS AUTHENTICATE")
//                        }
//                    }
//                )
//            }

            "PROMPT_ENCRYPT_SECURE_BIOMETRIC" -> {
                cancellationSignal = CancellationSignal()
                featureBiometric.authenticateSecure(
                    title = "Encrypt Biometric",
                    description = "This will encrypt your text into encrypted text",
                    negativeText = "Cancel",
                    alias = "fadlurahmanfdev",
                    cancellationSignal = cancellationSignal,
                    callBack = object : FeatureBiometricSecureCallBack {
                        override fun onSuccessAuthenticateEncryptSecureBiometric(
                            cipher: Cipher,
                            encodedIvKey: String
                        ) {
                            super.onSuccessAuthenticateEncryptSecureBiometric(cipher, encodedIvKey)
                            val encryptedPassword =
                                cipher.doFinal(plainText.toByteArray())
                            encodedEncryptedPassword =
                                Base64.encodeToString(encryptedPassword, Base64.NO_WRAP)
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
                                Toast.LENGTH_LONG
                            )
                            toast.show()
                        }

                        override fun onDialogClick(dialogInterface: DialogInterface?, which:Int) {
                            super.onDialogClick(dialogInterface, which)
                        }
                    }
                )
            }

//            "PROMPT_DECRYPT_SECURE_BIOMETRIC" -> {
//                corePlatformBiometricManager.promptDecrypt(
//                    title = "Decrypt Biometric",
//                    description = "This will decrypt your text into encrypted text",
//                    negativeText = "Cancel",
//                    encodedIvKey = encodedIvKey,
//                    callBack = object : CryptoBiometricCallBack {
//                        override fun onSuccessAuthenticateForDecrypt(cipher: Cipher) {
//                            super.onSuccessAuthenticateForDecrypt(cipher)
//                            println("ENCRYPTED PASSWORD: $encodedEncryptedPassword")
//                            val decodedPassword =
//                                Base64.decode(encodedEncryptedPassword, Base64.NO_WRAP)
//                            val plainPassword = String(cipher.doFinal(decodedPassword))
//                            println("PLAIN PASSWORD: $plainPassword")
//                        }
//                    })
//            }
        }
    }
}