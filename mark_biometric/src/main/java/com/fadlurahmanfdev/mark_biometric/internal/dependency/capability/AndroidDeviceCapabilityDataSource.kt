package com.fadlurahmanfdev.mark_biometric.internal.dependency.capability

import android.app.KeyguardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.hardware.fingerprint.FingerprintManager
import android.os.Build

internal class AndroidDeviceCapabilityDataSource(
    private val context: Context,
) : DeviceCapabilityDataSource {
    private val keyguardManager: KeyguardManager? =
        context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager

    private val fingerprintManager: FingerprintManager? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            context.getSystemService(Context.FINGERPRINT_SERVICE) as? FingerprintManager
        } else {
            null
        }

    private val biometricManager: BiometricManager? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            context.getSystemService(Context.BIOMETRIC_SERVICE) as? BiometricManager
        } else {
            null
        }

    override val sdkInt: Int = Build.VERSION.SDK_INT

    override fun hasSystemFeature(feature: String): Boolean {
        return context.packageManager.hasSystemFeature(feature)
    }

    override fun isFingerprintHardwareDetected(): Boolean {
        return fingerprintManager?.isHardwareDetected == true
    }

    override fun hasEnrolledFingerprints(): Boolean {
        return fingerprintManager?.hasEnrolledFingerprints() == true
    }

    override fun isDeviceSecure(): Boolean {
        return keyguardManager?.isDeviceSecure == true
    }

    override fun canAuthenticate(authenticator: Int): Int? {
        return biometricManager?.canAuthenticate(authenticator)
    }
}
