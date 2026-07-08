package com.fadlurahmanfdev.mark_biometric.internal.dependency.capability

internal interface DeviceCapabilityDataSource {
    val sdkInt: Int
    fun hasSystemFeature(feature: String): Boolean
    fun isFingerprintHardwareDetected(): Boolean
    fun hasEnrolledFingerprints(): Boolean
    fun isDeviceSecure(): Boolean
    fun canAuthenticate(authenticator: Int): Int?
}
