package com.fadlurahmanfdev.example.data

import androidx.annotation.DrawableRes

/**
 * UI model that represents one interactive library simulation item in the sample app.
 */
data class FeatureModel(
    @DrawableRes val featureIcon: Int,
    val action: FeatureAction,
    val title: String,
    val description: String,
)
