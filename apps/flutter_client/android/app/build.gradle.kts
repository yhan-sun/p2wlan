import java.util.Properties

plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "com.example.p2wlan_flutter_client"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        // TODO: Specify your own unique Application ID (https://developer.android.com/studio/build/application-id.html).
        applicationId = "com.example.p2wlan_flutter_client"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = 23
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    // Release builds must use the same private key for the lifetime of the
    // app. CI writes this file from GitHub Actions secrets. A debug-signed
    // release APK must never be produced accidentally: it cannot update the
    // installed app and is not suitable for distribution.
    val releaseSigningPropertiesFile = rootProject.file("key.properties")
    val releaseSigningProperties = Properties()
    if (releaseSigningPropertiesFile.isFile) {
        releaseSigningPropertiesFile.inputStream().use {
            releaseSigningProperties.load(it)
        }
    }
    val hasReleaseSigning = releaseSigningPropertiesFile.isFile
    val allowDebugReleaseSigning =
        System.getenv("P2WLAN_ALLOW_DEBUG_RELEASE_SIGNING") == "1"
    val releaseBuildRequested = gradle.startParameter.taskNames.any {
        it.contains("Release", ignoreCase = true)
    }

    if (releaseBuildRequested && !hasReleaseSigning && !allowDebugReleaseSigning) {
        throw GradleException(
            "Missing apps/flutter_client/android/key.properties. " +
                "A release APK must be signed with the stable P2WLAN key; " +
                "use a configured CI release or set " +
                "P2WLAN_ALLOW_DEBUG_RELEASE_SIGNING=1 only for local testing.",
        )
    }

    signingConfigs {
        create("release") {
            if (hasReleaseSigning) {
                storeFile = rootProject.file(
                    releaseSigningProperties.getProperty("storeFile"),
                )
                storePassword = releaseSigningProperties.getProperty("storePassword")
                keyAlias = releaseSigningProperties.getProperty("keyAlias")
                keyPassword = releaseSigningProperties.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            signingConfig = if (hasReleaseSigning) {
                signingConfigs.getByName("release")
            } else {
                // This branch is opt-in for local testing only; the guard
                // above prevents it from being used accidentally.
                signingConfigs.getByName("debug")
            }
        }
    }
}

val buildP2wlanNative by tasks.registering(Exec::class) {
    inputs.property("P2WLAN_ANDROID_ABIS", System.getenv("P2WLAN_ANDROID_ABIS") ?: "all")
    inputs.files(
        rootProject.file("../../../Cargo.toml"),
        rootProject.file("../../../Cargo.lock"),
        rootProject.file("../../../client"),
        rootProject.file("../../../scripts/build_android_native.sh"),
    )
    outputs.dir(project.file("src/main/jniLibs"))
    commandLine(
        "bash",
        rootProject.file("../../../scripts/build_android_native.sh").absolutePath,
    )
}

tasks.named("preBuild").configure {
    dependsOn(buildP2wlanNative)
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}
