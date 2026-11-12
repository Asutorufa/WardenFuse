plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.github.asutorufa.wardenfuse"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.asutorufa.wardenfuse"
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = (project.findProperty("appVersion") as String?) ?: "0.1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation("com.google.android.material:material:1.13.0")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    testImplementation("junit:junit:4.13.2")
}
