import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.util.Properties
import java.util.UUID

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

dependencies {
    testImplementation("junit:junit:4.13.2")
}

val sourceIdentityKeys = listOf(
    "P2WLAN_SOURCE_GIT_COMMIT",
    "P2WLAN_SOURCE_BUILD_ID",
    "P2WLAN_SOURCE_DIRTY",
    "P2WLAN_SOURCE_DIFF_HASH",
)
val sourceIdentityNonceKey = "P2WLAN_SOURCE_IDENTITY_NONCE"
val sourceIdentityFileProperty = providers.gradleProperty("p2wlanSourceIdentityFile")
val sourceIdentityNonceProperty = providers.gradleProperty("p2wlanSourceIdentityNonce")
val hasSourceIdentityFile = sourceIdentityFileProperty.isPresent
val hasSourceIdentityNonce = sourceIdentityNonceProperty.isPresent

if (hasSourceIdentityFile != hasSourceIdentityNonce) {
    throw GradleException(
        "p2wlanSourceIdentityFile and p2wlanSourceIdentityNonce must be provided together",
    )
}

val sourceIdentityFile = if (hasSourceIdentityFile) {
    val rawPath = sourceIdentityFileProperty.get()
    if (rawPath.isBlank()) {
        throw GradleException("p2wlanSourceIdentityFile must not be blank")
    }
    // Check the caller's raw string before any Gradle path resolution.  Calling
    // rootProject.file() first would turn a relative path into an absolute one
    // and make this validation meaningless.
    val rawFile = File(rawPath)
    if (!rawFile.isAbsolute) {
        throw GradleException("p2wlanSourceIdentityFile must be an absolute path")
    }
    val candidate = rawFile
    if (!Files.isRegularFile(candidate.toPath(), LinkOption.NOFOLLOW_LINKS)) {
        throw GradleException(
            "p2wlanSourceIdentityFile must name a regular, non-symlink file: $rawPath",
        )
    }
    candidate
} else {
    null
}

val sourceIdentityNonce = if (hasSourceIdentityNonce) {
    sourceIdentityNonceProperty.get()
} else {
    null
}

val sourceIdentityValues = if (sourceIdentityFile != null) {
    val allowedKeys = (sourceIdentityKeys + sourceIdentityNonceKey).toSet()
    val values = linkedMapOf<String, String>()
    sourceIdentityFile.readLines().forEachIndexed { index, line ->
        if (line.isBlank() || line.startsWith("#")) {
            return@forEachIndexed
        }
        val separator = line.indexOf('=')
        if (separator <= 0) {
            throw GradleException(
                "Malformed source identity snapshot at ${sourceIdentityFile.path}:${index + 1}",
            )
        }
        val key = line.substring(0, separator)
        if (key !in allowedKeys) {
            throw GradleException(
                "Unexpected source identity key $key at ${sourceIdentityFile.path}:${index + 1}",
            )
        }
        if (values.containsKey(key)) {
            throw GradleException(
                "Duplicate source identity key $key in ${sourceIdentityFile.path}",
            )
        }
        values[key] = line.substring(separator + 1)
    }
    (sourceIdentityKeys + sourceIdentityNonceKey).forEach { key ->
        if (!values.containsKey(key)) {
            throw GradleException(
                "Source identity snapshot is missing $key: ${sourceIdentityFile.path}",
            )
        }
    }
    values
} else {
    emptyMap()
}

if (sourceIdentityFile != null) {
    val expectedNonce = sourceIdentityNonce!!
    if (!Regex("[0-9a-f]{32}").matches(expectedNonce)) {
        throw GradleException("p2wlanSourceIdentityNonce must be 32 lowercase hexadecimal characters")
    }
    if (sourceIdentityValues[sourceIdentityNonceKey] != expectedNonce) {
        throw GradleException(
            "p2wlanSourceIdentityNonce does not match the source identity snapshot",
        )
    }

    val commit = sourceIdentityValues.getValue("P2WLAN_SOURCE_GIT_COMMIT")
    val buildId = sourceIdentityValues.getValue("P2WLAN_SOURCE_BUILD_ID")
    val dirty = sourceIdentityValues.getValue("P2WLAN_SOURCE_DIRTY")
    val diffHash = sourceIdentityValues.getValue("P2WLAN_SOURCE_DIFF_HASH")
    if (!Regex("[0-9A-Fa-f]{40}").matches(commit)) {
        throw GradleException("P2WLAN_SOURCE_GIT_COMMIT is not a 40-character hexadecimal SHA-1")
    }
    if (dirty != "true" && dirty != "false") {
        throw GradleException("P2WLAN_SOURCE_DIRTY must be exactly true or false")
    }
    if (dirty == "true" && !Regex("[0-9A-Fa-f]{40}").matches(diffHash)) {
        throw GradleException("dirty source identity requires a 40-character hexadecimal diff hash")
    }
    if (dirty == "false" && diffHash.isNotEmpty()) {
        throw GradleException("clean source identity requires an empty diff hash")
    }
    val expectedBuildId = if (dirty == "true") {
        "${commit.substring(0, 12)}-dirty-${diffHash.substring(0, 12)}"
    } else {
        commit.substring(0, 12)
    }
    if (buildId != expectedBuildId) {
        throw GradleException(
            "P2WLAN_SOURCE_BUILD_ID does not match the source identity fields",
        )
    }
}

val buildP2wlanNative by tasks.registering(Exec::class) {
    val directBuild = sourceIdentityFile == null

    inputs.property("P2WLAN_ANDROID_ABIS", System.getenv("P2WLAN_ANDROID_ABIS") ?: "all")
    inputs.property("p2wlanSourceIdentityFile", sourceIdentityFile?.absolutePath ?: "")
    inputs.property("p2wlanSourceIdentityNonce", sourceIdentityNonce ?: "")
    sourceIdentityKeys.forEach { key ->
        inputs.property(key, sourceIdentityValues[key] ?: "")
    }
    if (sourceIdentityFile != null) {
        inputs.file(sourceIdentityFile)
    }
    inputs.files(
        rootProject.file("../../../Cargo.toml"),
        rootProject.file("../../../Cargo.lock"),
        rootProject.file("../../../client"),
        rootProject.file("../../../scripts/build_android_native.sh"),
    )
    outputs.dir(project.file("src/main/jniLibs"))
    if (directBuild) {
        // A direct build has no frozen identity input that Gradle can compare.
        // It must execute so Cargo can inspect the current checkout every time.
        outputs.upToDateWhen { false }
        outputs.doNotCacheIf("direct native builds use live Git identity") { true }
    }
    commandLine(
        "bash",
        rootProject.file("../../../scripts/build_android_native.sh").absolutePath,
    )
    sourceIdentityKeys.forEach { key ->
        if (sourceIdentityFile != null) {
            environment(key, sourceIdentityValues.getValue(key))
        } else {
            // Do not let a shell's old override leak into an unwrapped direct
            // build.  With no explicit snapshot, build.rs must inspect Git.
            environment.remove(key)
        }
    }
    if (directBuild) {
        // Generate this at task execution time, not during configuration, so
        // an existing daemon/configuration cache cannot freeze one refresh.
        doFirst {
            environment("P2WLAN_SOURCE_IDENTITY_REFRESH", UUID.randomUUID().toString())
        }
    } else {
        // A shell-level refresh must never alter an explicitly frozen build.
        environment.remove("P2WLAN_SOURCE_IDENTITY_REFRESH")
    }
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
