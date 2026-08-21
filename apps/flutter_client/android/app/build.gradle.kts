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

    buildTypes {
        release {
            // TODO: Add your own signing config for the release build.
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

val buildP2wlanNative by tasks.registering(Exec::class) {
    inputs.files(
        rootProject.file("../../../Cargo.toml"),
        rootProject.file("../../../Cargo.lock"),
        rootProject.file("../../../client"),
        rootProject.file("../../../scripts/build_android_native.sh"),
    )
    outputs.files(
        project.file("src/main/jniLibs/arm64-v8a/libp2wlan_android.so"),
        project.file("src/main/jniLibs/armeabi-v7a/libp2wlan_android.so"),
        project.file("src/main/jniLibs/x86_64/libp2wlan_android.so"),
    )
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
