import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// The Swell Protocol library: Apache-2.0, no app code inside (see LICENSE). Pure Kotlin/JVM so the same bytes run in the
// Android app, in the JVM peer used by tests, and in the cross-implementation vector tests.
plugins {
    id("org.jetbrains.kotlin.jvm")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

dependencies {
    // X25519 and ML-KEM-768 (FIPS 203): BouncyCastle, MIT licence. Lightweight API only, so Android's built-in "BC" provider is never touched.
    api("org.bouncycastle:bcprov-jdk18on:1.79")
    testImplementation(kotlin("test-junit"))
    // JSON reader for the shared vectors in docs/protocol-vectors/ (tests only).
    testImplementation("org.json:json:20240303")
}
