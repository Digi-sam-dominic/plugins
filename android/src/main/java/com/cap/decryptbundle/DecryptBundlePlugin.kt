package com.cap.decryptbundle

import android.util.Base64
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.CapacitorPlugin
import java.io.File
import java.nio.charset.StandardCharsets
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

@CapacitorPlugin(name = "DecryptBundle")
class DecryptBundlePlugin : Plugin() {

    @PluginMethod
    fun decrypt(call: PluginCall) {
        try {
            val request = DecryptRequest.from(call)
            val inputFile = File(context.filesDir, "encrypted-bundles/${request.assessmentId}/bundle.exb")

            if (!inputFile.exists()) {
                call.reject("EXB file not found")
                return
            }

            val exb = inputFile.readBytes()
            val headerEnd = readHeaderEnd(exb)
            val ciphertextEnd = exb.size - AUTH_TAG_LENGTH

            if (ciphertextEnd <= headerEnd) {
                call.reject("Corrupted EXB payload")
                return
            }

            val ciphertext = exb.copyOfRange(headerEnd, ciphertextEnd)
            val decrypted = decryptBundle(request, ciphertext)

            val outputFile = File(
                context.filesDir,
                "encrypted-bundles/${request.assessmentId}/decrypted/bundle.zip"
            )
            outputFile.parentFile?.mkdirs()
            outputFile.writeBytes(decrypted)

            call.resolve(JSObject().apply {
                put("path", outputFile.absolutePath)
            })
        } catch (error: IllegalArgumentException) {
            call.reject(error.message ?: "Invalid input")
        } catch (error: Exception) {
            call.reject("Decryption failed: ${error.message}")
        }
    }

    private fun decryptBundle(request: DecryptRequest, ciphertext: ByteArray): ByteArray {
        // The EXB file carries the ciphertext body, while the GCM tag is supplied separately.
        val combined = ByteArray(ciphertext.size + request.tag.size)
        System.arraycopy(ciphertext, 0, combined, 0, ciphertext.size)
        System.arraycopy(request.tag, 0, combined, ciphertext.size, request.tag.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val key = SecretKeySpec(request.cek, "AES")
        val spec = GCMParameterSpec(AUTH_TAG_LENGTH_BITS, request.iv)
        // AAD must stay byte-for-byte aligned with the producer.
        val aad = "${request.examId}|${request.sessionId}|bundle".toByteArray(StandardCharsets.UTF_8)

        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        cipher.updateAAD(aad)

        return cipher.doFinal(combined)
    }

    private fun readHeaderEnd(exb: ByteArray): Int {
        if (exb.size < HEADER_PREFIX_LENGTH) {
            throw IllegalArgumentException("Invalid EXB format")
        }

        val isExb1 =
            exb[0] == 'E'.code.toByte() &&
                exb[1] == 'X'.code.toByte() &&
                exb[2] == 'B'.code.toByte() &&
                exb[3] == '1'.code.toByte()

        if (!isExb1) {
            throw IllegalArgumentException("Invalid EXB format")
        }

        // Bytes 4-7 store the EXB header length as little-endian UInt32.
        val headerLength =
            (exb[4].toInt() and 0xff) or
                ((exb[5].toInt() and 0xff) shl 8) or
                ((exb[6].toInt() and 0xff) shl 16) or
                ((exb[7].toInt() and 0xff) shl 24)

        val headerEnd = HEADER_PREFIX_LENGTH + headerLength
        if (headerEnd >= exb.size) {
            throw IllegalArgumentException("Corrupted EXB header")
        }

        return headerEnd
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
    }
}
