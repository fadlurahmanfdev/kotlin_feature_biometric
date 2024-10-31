package com.fadlurahmanfdev.example

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.util.Base64
import android.util.Log
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.recyclerview.widget.RecyclerView
import com.fadlurahmanfdev.example.data.FeatureModel
import com.fadlurahmanfdev.example.presentation.ListExampleAdapter
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.AuthenticationCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.FeatureBiometricCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.FeatureBiometricDecryptSecureCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.FeatureBiometricEncryptSecureCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.SecureAuthenticationDecryptCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.callback.SecureAuthenticationEncryptCallBack
import com.fadlurahmanfdev.kotlin_feature_identity.data.enums.FeatureAuthenticatorType
import com.fadlurahmanfdev.kotlin_feature_identity.data.exception.FeatureBiometricException
import com.fadlurahmanfdev.kotlin_feature_identity.data.exception.FeatureIdentityException
import com.fadlurahmanfdev.kotlin_feature_identity.plugin.FeatureAuthentication
import com.fadlurahmanfdev.kotlin_feature_identity.plugin.FeatureAuthenticationRepository
import com.fadlurahmanfdev.kotlin_feature_identity.plugin.KotlinFeatureBiometric
import javax.crypto.Cipher

class MainActivity : AppCompatActivity(), ListExampleAdapter.Callback {
    @Deprecated(message = "Replace with FeatureAuthentication")
    lateinit var featureBiometric: KotlinFeatureBiometric
    lateinit var featureAuthentication: FeatureAuthenticationRepository

    private val features: List<FeatureModel> = listOf<FeatureModel>(
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Is Device Support Fingerprint?",
            desc = "Check whether device support fingerprint",
            enum = "DEVICE_SUPPORT_FINGERPRINT"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Is Device Support Face Authentication?",
            desc = "Check whether device support face authentication",
            enum = "DEVICE_SUPPORT_FACE_AUTHENTICATION"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Is Device Support Biometric?",
            desc = "Check whether device support biometric",
            enum = "DEVICE_SUPPORT_BIOMETRIC"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Is Fingerprint Enrolled?",
            desc = "Check whether fingerprint enrolled",
            enum = "IS_FINGERPRINT_ENROLLED"
        ),


        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Check Biometric Authentication Status",
            desc = "Check status biometric authentication",
            enum = "CHECK_BIOMETRIC_AUTHENTICATION_STATUS"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Check Device Credential Authentication Status",
            desc = "Check whether device can authenticate using Device Credential",
            enum = "CHECK_DEVICE_CREDENTIAL_AUTHENTICATION_STATUS"
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
            title = "Is Biometric Changed?",
            desc = "Check whether new fingerprint/biometric added/changed",
            enum = "IS_BIOMETRIC_CHANGED"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Encrypted Biometric",
            desc = "Prompt encrypted biometric",
            enum = "PROMPT_ENCRYPT_BIOMETRIC"
        ),
        FeatureModel(
            featureIcon = R.drawable.baseline_developer_mode_24,
            title = "Decrypted Biometric",
            desc = "Prompt decrypted biometric",
            enum = "PROMPT_DECRYPT_BIOMETRIC"
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
        featureAuthentication = FeatureAuthentication(this)
    }

    private lateinit var cancellationSignal: CancellationSignal
    private val plainText = "PASSW0RD"
    private lateinit var encodedEncryptedPassword: String
    private lateinit var encodedIvKey: String

    override fun onClicked(item: FeatureModel) {
        when (item.enum) {
            "DEVICE_SUPPORT_FINGERPRINT" -> {
                val isSupported = featureAuthentication.isDeviceSupportFingerprint()
                Log.d(
                    this::class.java.simpleName,
                    "is device support fingerprint: $isSupported"
                )
            }

            "DEVICE_SUPPORT_FACE_AUTHENTICATION" -> {
                val isSupported = featureAuthentication.isDeviceSupportFaceAuth()
                Log.d(
                    this::class.java.simpleName,
                    "is device support face auth: $isSupported"
                )
            }

            "DEVICE_SUPPORT_BIOMETRIC" -> {
                val isSupported = featureAuthentication.isDeviceSupportBiometric()
                Log.d(
                    this::class.java.simpleName,
                    "is device support biometric: $isSupported"
                )
            }

            "IS_FINGERPRINT_ENROLLED" -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    val isEnrolled = featureAuthentication.isFingerprintEnrolled()
                    Log.d(
                        this::class.java.simpleName,
                        "is fingerprint enrolled: $isEnrolled"
                    )
                }
            }

            "CHECK_BIOMETRIC_AUTHENTICATION_STATUS" -> {
                val status =
                    featureAuthentication.checkAuthenticatorStatus(FeatureAuthenticatorType.BIOMETRIC)
                Log.d(
                    this::class.java.simpleName,
                    "biometric authentication status: $status"
                )
            }

            "CHECK_DEVICE_CREDENTIAL_AUTHENTICATION_STATUS" -> {
                val status =
                    featureAuthentication.checkAuthenticatorStatus(FeatureAuthenticatorType.DEVICE_CREDENTIAL)
                Log.d(
                    this::class.java.simpleName,
                    "device credential authentication status: $status"
                )
            }

            "CAN_AUTHENTICATE_USING_BIOMETRIC" -> {
                val canAuthenticate =
                    featureAuthentication.canAuthenticate(FeatureAuthenticatorType.BIOMETRIC)
                Log.d(
                    this::class.java.simpleName,
                    "can authenticate using biometric: $canAuthenticate"
                )
            }

            "CAN_AUTHENTICATE_USING_DEVICE_CREDENTIAL" -> {
                val canAuthenticate =
                    featureBiometric.canAuthenticate(FeatureAuthenticatorType.DEVICE_CREDENTIAL)
                Log.d(
                    this::class.java.simpleName,
                    "can authenticate using device credential: $canAuthenticate"
                )
            }

            "PROMPT_WEAK_BIOMETRIC" -> {
                cancellationSignal = CancellationSignal()
                featureAuthentication.authenticateBiometric(
                    title = "Title - Weak Biometric",
                    description = "Desc - Weak Biometric",
                    subTitle = "SubTitle - Weak Biometric",
                    negativeText = "Negative Text",
                    confirmationRequired = false,
                    callBack = object : AuthenticationCallBack {
                        override fun onSuccessAuthenticate() {
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Success authenticate",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }
                    }
                )
            }

            "PROMPT_CREDENTIAL_BIOMETRIC" -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    featureAuthentication.authenticateDeviceCredential(
                        title = "Title - Device Credential",
                        subTitle = "Sub Title - Device Credential",
                        description = "Desc - Device Credential",
                        negativeText = "Negative Text",
                        confirmationRequired = false,
                        callBack = object : AuthenticationCallBack {
                            override fun onSuccessAuthenticate() {
                                val toast = Toast.makeText(
                                    this@MainActivity,
                                    "Success authenticate",
                                    Toast.LENGTH_SHORT
                                )
                                toast.show()
                            }
                        }
                    )
                }
//                featureBiometric.authenticate(
//                    title = "Encrypt Biometric",
//                    description = "Authenticate using your credential",
//                    negativeText = "Cancel",
//                    type = FeatureAuthenticatorType.DEVICE_CREDENTIAL,
//                    cancellationSignal = cancellationSignal,
//                    callBack = object : FeatureBiometricCallBack {
//                        override fun onSuccessAuthenticate() {
//                            val toast = Toast.makeText(
//                                this@MainActivity,
//                                "Successfully Authenticate ${FeatureAuthenticatorType.DEVICE_CREDENTIAL}",
//                                Toast.LENGTH_SHORT
//                            )
//                            toast.show()
//                        }
//                    }
//                )
            }

//            "GENERATE_SECRET_KEY" -> {
//                featureBiometric.generateSecretKey("fadlurahmanfdev")
//                val toast = Toast.makeText(
//                    this@MainActivity,
//                    "Successfully generate secret key",
//                    Toast.LENGTH_SHORT
//                )
//                toast.show()
//            }

            "IS_BIOMETRIC_CHANGED" -> {
                val isBiometricChanged = featureBiometric.isBiometricChanged("fadlurahmanfdev")
                Log.d(this::class.java.simpleName, "is biometric changed: $isBiometricChanged")
            }

            "PROMPT_ENCRYPT_BIOMETRIC" -> {
                featureAuthentication.secureAuthenticateBiometricEncrypt(
                    title = "Title - Encrypt Biometric",
                    subTitle = "Sub Title - Encrypt Biometric",
                    description = "Desc - Encrypt Biometric",
                    negativeText = "Cancel",
                    alias = "fadlurahmanfdev",
                    confirmationRequired = false,
                    callBack = object : SecureAuthenticationEncryptCallBack {
                        override fun onSuccessAuthenticate(
                            cipher: Cipher,
                            encodedIVKey: String
                        ) {
                            encodedEncryptedPassword = featureAuthentication.encrypt(cipher, plainText)
                            this@MainActivity.encodedIvKey = encodedIVKey
                            Log.d(
                                this@MainActivity::class.java.simpleName,
                                "encoded iv key: ${this@MainActivity.encodedIvKey}"
                            )
                            Log.d(
                                this@MainActivity::class.java.simpleName,
                                "encoded encrypted password: $encodedEncryptedPassword"
                            )
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Successfully Encrypted Authenticate",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }
                    }
                )
            }

            "PROMPT_DECRYPT_BIOMETRIC" -> {
                featureAuthentication.secureAuthenticateBiometricDecrypt(
                    alias = "fadlurahmanfdev",
                    encodedIVKey = encodedIvKey,
                    title = "Title - Decrypt Biometric",
                    subTitle = "Sub Title - Decrypt Biometric",
                    description = "Desc - Decrypt Biometric",
                    negativeText = "Cancel",
                    confirmationRequired = false,
                    callBack = object : SecureAuthenticationDecryptCallBack {
                        override fun onSuccessAuthenticate(cipher: Cipher) {
//                            val decodedPassword =
//                                Base64.decode(encodedEncryptedPassword, Base64.NO_WRAP)
//                            val plainPassword = featureAuthentication.decrypt(cipher, decodedPassword)
//                            Log.d(
//                                this@MainActivity::class.java.simpleName,
//                                "DECRYPTED PASSWORD: $plainPassword"
//                            )
//                            val toast = Toast.makeText(
//                                this@MainActivity,
//                                "Successfully Decrypt",
//                                Toast.LENGTH_SHORT
//                            )
//                            toast.show()

                            val plainPassword = featureAuthentication.decrypt(cipher, encodedEncryptedPassword)
                            Log.d(
                                this@MainActivity::class.java.simpleName,
                                "decrypted password: $plainPassword"
                            )
                            val toast = Toast.makeText(
                                this@MainActivity,
                                "Successfully Decrypted Authenticate",
                                Toast.LENGTH_SHORT
                            )
                            toast.show()
                        }

                        override fun onErrorAuthenticate(exception: FeatureIdentityException) {
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