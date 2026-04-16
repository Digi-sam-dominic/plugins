package com.cap.decryptbundle

import android.util.Base64
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.CapacitorPlugin
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.util.zip.ZipFile
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.min

@CapacitorPlugin(name = "DecryptBundle")
class DecryptBundlePlugin : Plugin() {

    @PluginMethod
    fun decrypt(call: PluginCall) {
        try {
            val request = DecryptRequest.from(call)
            val relativeBundlePath = "encrypted-bundles/${request.assessmentId}/bundle.exb"
            val relativeOutputPath = "encrypted-bundles/${request.assessmentId}/decrypted/bundle.zip"
            val inputFile = File(context.filesDir, relativeBundlePath)

            if (!inputFile.exists()) {
                call.reject("EXB file not found")
                return
            }

            val outputFile = File(context.filesDir, relativeOutputPath)
            outputFile.parentFile?.mkdirs()

            if (request.iv.size != GCM_IV_LENGTH) {
                throw IllegalArgumentException("Invalid IV length")
            }
            if (request.cek.isEmpty()) {
                throw IllegalArgumentException("Invalid CEK")
            }

            if (outputFile.exists()) {
                outputFile.delete()
            }

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val key = SecretKeySpec(request.cek, "AES")
            val spec = GCMParameterSpec(AUTH_TAG_LENGTH_BITS, request.iv)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)

            val aad = "${request.examId}|${request.sessionId}|bundle".toByteArray(StandardCharsets.UTF_8)
            cipher.updateAAD(aad)

            FileInputStream(inputFile).use { input ->
                FileOutputStream(outputFile).use { output ->
                    val prefix = ByteArray(HEADER_PREFIX_LENGTH)
                    if (input.read(prefix) != HEADER_PREFIX_LENGTH) {
                        throw IllegalArgumentException("Invalid EXB format")
                    }

                    val isExb1 =
                        prefix[0] == 'E'.code.toByte() &&
                            prefix[1] == 'X'.code.toByte() &&
                            prefix[2] == 'B'.code.toByte() &&
                            prefix[3] == '1'.code.toByte()

                    if (!isExb1) {
                        throw IllegalArgumentException("Invalid EXB format")
                    }

                    val headerLen =
                        (prefix[4].toInt() and 0xff) or
                            ((prefix[5].toInt() and 0xff) shl 8) or
                            ((prefix[6].toInt() and 0xff) shl 16) or
                            ((prefix[7].toInt() and 0xff) shl 24)

                    if (headerLen < 0) {
                        throw IllegalArgumentException("Corrupted EXB header")
                    }

                    var remainingHeader = headerLen
                    val headerReadBuffer = ByteArray(8192)
                    while (remainingHeader > 0) {
                        val read = input.read(headerReadBuffer, 0, min(headerReadBuffer.size, remainingHeader))
                        if (read <= 0) {
                            throw IllegalArgumentException("Invalid EXB header")
                        }
                        remainingHeader -= read
                    }

                    val totalSize = inputFile.length()
                    val overhead =
                        HEADER_PREFIX_LENGTH.toLong() + headerLen.toLong() + AUTH_TAG_LENGTH
                    val cipherSize = totalSize - overhead

                    if (cipherSize <= 0L || cipherSize > totalSize) {
                        throw IllegalArgumentException("Corrupted EXB payload")
                    }

                    val buffer = ByteArray(64 * 1024)
                    var processed = 0L

                    while (processed < cipherSize) {
                        val toRead = min(buffer.size.toLong(), cipherSize - processed).toInt()
                        val read = input.read(buffer, 0, toRead)
                        if (read <= 0) {
                            throw IllegalArgumentException("Unexpected end of EXB payload")
                        }

                        val block = cipher.update(buffer, 0, read)
                        if (block != null) {
                            output.write(block)
                        }

                        processed += read
                    }

                    val finalBlock = cipher.doFinal(request.tag)
                    if (finalBlock != null) {
                        output.write(finalBlock)
                    }
                }
            }

            val decryptedDir = outputFile.parentFile
                ?: throw IllegalStateException("Invalid decrypted output path")

            extractZipSecure(outputFile, decryptedDir)
            ensureAssessmentJsonAtRoot(decryptedDir)

            val relativeDecryptedDir = "encrypted-bundles/${request.assessmentId}/decrypted"
            call.resolve(JSObject().apply { put("path", relativeDecryptedDir) })
        } catch (error: IllegalArgumentException) {
            call.reject(error.message ?: "Invalid input")
        } catch (error: Exception) {
            call.reject("Decrypt failed: ${error.message}")
        }
    }

    /**
     * Stream-decrypted ZIP is expanded on disk only (no bridge to JS). Guards against zip-slip.
     */
    private fun extractZipSecure(zipFile: File, destDir: File) {
        if (!destDir.exists()) {
            destDir.mkdirs()
        }
        val canonicalDest = destDir.canonicalFile
        ZipFile(zipFile).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                val outFile = File(destDir, entry.name)
                val canonicalOut = outFile.canonicalFile
                val destPrefix = canonicalDest.path + File.separator
                if (!canonicalOut.path.startsWith(destPrefix) && canonicalOut != canonicalDest) {
                    throw SecurityException("Illegal zip entry: ${entry.name}")
                }
                if (entry.isDirectory) {
                    outFile.mkdirs()
                } else {
                    outFile.parentFile?.mkdirs()
                    zip.getInputStream(entry).use { input ->
                        FileOutputStream(outFile).use { output ->
                            input.copyTo(output)
                        }
                    }
                }
            }
        }
    }

    /** Capacitor loader expects [decrypted]/assessment.json; copy from subtree if the archive nests it. */
    private fun ensureAssessmentJsonAtRoot(destDir: File) {
        val root = File(destDir, "assessment.json")
        if (root.isFile) {
            return
        }
        val nested = destDir.walk().maxDepth(6).firstOrNull { candidate ->
            candidate.isFile && candidate.name == "assessment.json"
        }
        if (nested != null) {
            nested.copyTo(root, overwrite = true)
        }
        if (!root.isFile) {
            throw IllegalStateException("ZIP did not contain assessment.json")
        }
    }

    private data class DecryptRequest(
        val assessmentId: String,
        val cek: ByteArray,
        val iv: ByteArray,
        val tag: ByteArray,
        val examId: String,
        val sessionId: String
    ) {
        companion object {
            fun from(call: PluginCall): DecryptRequest {
                val assessmentId = call.getString("assessmentId")
                    ?: throw IllegalArgumentException("Missing assessmentId")
                val cek = decodeBase64(call.getString("cek"), "cek")
                val iv = decodeBase64(call.getString("iv"), "iv")
                val tag = decodeBase64(call.getString("tag"), "tag")
                val examId = call.getString("examId")
                    ?: throw IllegalArgumentException("Missing examId")
                val sessionId = call.getString("sessionId")
                    ?: throw IllegalArgumentException("Missing sessionId")

                return DecryptRequest(
                    assessmentId = assessmentId,
                    cek = cek,
                    iv = iv,
                    tag = tag,
                    examId = examId,
                    sessionId = sessionId
                )
            }

            private fun decodeBase64(value: String?, fieldName: String): ByteArray {
                val encodedValue = value ?: throw IllegalArgumentException("Missing $fieldName")

                return try {
                    Base64.decode(encodedValue, Base64.NO_WRAP)
                } catch (_: IllegalArgumentException) {
                    throw IllegalArgumentException("Invalid base64 for $fieldName")
                }
            }
        }
    }

    companion object {
        private const val HEADER_PREFIX_LENGTH = 8
        private const val AUTH_TAG_LENGTH = 16
        private const val AUTH_TAG_LENGTH_BITS = AUTH_TAG_LENGTH * 8
        private const val GCM_IV_LENGTH = 12
    }
}
