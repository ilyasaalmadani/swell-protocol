import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// Fuzz targets for the Swell Protocol library (Jazzer / libFuzzer, OSS-Fuzz). Not part of the published library.
// Each target is an `object XFuzzer` with `@JvmStatic fun fuzzerTestOneInput(data: ByteArray)`; it needs no Jazzer API at compile time.
//
//   ./gradlew :fuzz:fuzzJars     the fuzz jar and its runtime classpath in fuzz/build/fuzz-out (what OSS-Fuzz copies to $OUT)
//   ./gradlew :fuzz:seedCorpus   seed corpora from docs/protocol-vectors in fuzz/build/seeds/<Target>/
//   ./gradlew :fuzz:replay       runs every target over its seeds and over fuzz/regressions/<Target>/ (no Jazzer needed)
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
    implementation(project(":swellprotocol"))
    // JSON reader for the seed corpus generator (SeedCorpus.kt) only.
    implementation("org.json:json:20260814")
}

val vectors = rootProject.projectDir.resolve("../docs/protocol-vectors")
val seeds = layout.buildDirectory.dir("seeds")

tasks.register<Sync>("fuzzJars") {
    description = "The fuzz jar and its runtime classpath, for OSS-Fuzz build.sh."
    from(tasks.named("jar"))
    from(configurations.named("runtimeClasspath"))
    into(layout.buildDirectory.dir("fuzz-out"))
}

tasks.register<JavaExec>("seedCorpus") {
    description = "Writes the seed corpora from docs/protocol-vectors."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.jijilabsdigital.swell.protocol.fuzz.SeedCorpus")
    args(vectors.absolutePath, seeds.get().asFile.absolutePath)
}

tasks.register<JavaExec>("replay") {
    description = "Runs every fuzz target over its seed corpus and the saved regression inputs."
    dependsOn("seedCorpus")
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.jijilabsdigital.swell.protocol.fuzz.Replay")
    args(seeds.get().asFile.absolutePath, projectDir.resolve("regressions").absolutePath)
}
