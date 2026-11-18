// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PT Jiji Labs Digital

package com.jijilabsdigital.swell.protocol.fuzz

import java.io.File

/**
 * Runs every target over the files in `<dir>/<Target>/` for each directory given (seed corpora, saved regressions, a crash file's
 * directory). No fuzzing engine is needed, so this is the regression test of the fuzz targets. Exit code 1 on any finding.
 */
object Replay {
    val targets: Map<String, (ByteArray) -> Unit> = linkedMapOf(
        "WireFuzzer" to WireFuzzer::fuzzerTestOneInput,
        "CodecFuzzer" to CodecFuzzer::fuzzerTestOneInput,
        "HandshakeFuzzer" to HandshakeFuzzer::fuzzerTestOneInput,
        "RatchetFuzzer" to RatchetFuzzer::fuzzerTestOneInput,
        "SessionRecordFuzzer" to SessionRecordFuzzer::fuzzerTestOneInput,
        "SignatureFuzzer" to SignatureFuzzer::fuzzerTestOneInput,
        "InviteFuzzer" to InviteFuzzer::fuzzerTestOneInput,
        "LinkFuzzer" to LinkFuzzer::fuzzerTestOneInput,
    )

    @JvmStatic
    fun main(args: Array<String>) {
        var failed = 0; var ran = 0
        for (root in args.map(::File)) {
            for ((name, run) in targets) {
                val files = File(root, name).listFiles()?.filter { it.isFile }?.sorted() ?: continue
                for (file in files) {
                    ran++
                    try { run(file.readBytes()) } catch (t: Throwable) {
                        failed++
                        System.err.println("FINDING $name ${file.path}: $t")
                        t.stackTrace.take(8).forEach { System.err.println("    at $it") }
                    }
                }
            }
        }
        println("replayed $ran inputs, $failed findings")
        if (failed > 0) kotlin.system.exitProcess(1)
    }
}
