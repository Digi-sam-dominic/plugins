import Foundation
import Capacitor
import CryptoKit

@objc(DecryptBundlePlugin)
public class DecryptBundlePlugin: CAPPlugin, CAPBridgedPlugin {
    public let identifier = "DecryptBundlePlugin"
    public let jsName = "DecryptBundle"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "decrypt", returnType: CAPPluginReturnPromise)
    ]
    private let implementation = DecryptBundleFileDecryptor()

    @objc func decrypt(_ call: CAPPluginCall) {
        do {
            let request = try DecryptBundleRequest(call: call)
            let outputURL = try implementation.decrypt(request: request)

            call.resolve([
                "path": outputURL.path
            ])
        } catch let error as DecryptBundleError {
            call.reject(error.message)
        } catch {
            call.reject("Decryption failed: \(error.localizedDescription)")
        }
    }
}

struct DecryptBundleRequest {
    let assessmentId: String
    let cek: Data
    let iv: Data
    let tag: Data
    let examId: String
    let sessionId: String

    init(
        assessmentId: String,
        cek: Data,
        iv: Data,
        tag: Data,
        examId: String,
        sessionId: String
    ) {
        self.assessmentId = assessmentId
        self.cek = cek
        self.iv = iv
        self.tag = tag
        self.examId = examId
        self.sessionId = sessionId
    }

    init(call: CAPPluginCall) throws {
        assessmentId = try Self.requiredString(call.getString("assessmentId"), field: "assessmentId")
        cek = try Self.decodeBase64(call.getString("cek"), field: "cek")
        iv = try Self.decodeBase64(call.getString("iv"), field: "iv")
        tag = try Self.decodeBase64(call.getString("tag"), field: "tag")
        examId = try Self.requiredString(call.getString("examId"), field: "examId")
        sessionId = try Self.requiredString(call.getString("sessionId"), field: "sessionId")
    }

    private static func requiredString(_ value: String?, field: String) throws -> String {
        guard let value, !value.isEmpty else {
            throw DecryptBundleError("Missing \(field)")
        }
        return value
    }

    private static func decodeBase64(_ value: String?, field: String) throws -> Data {
        guard let value, let data = Data(base64Encoded: value) else {
            throw DecryptBundleError("Invalid base64 for \(field)")
        }
        return data
    }
}

final class DecryptBundleFileDecryptor {
    private let fileManager: FileManager

    init(fileManager: FileManager = .default) {
        self.fileManager = fileManager
    }

    func decrypt(
        request: DecryptBundleRequest,
        baseDirectory: URL? = nil
    ) throws -> URL {
        let rootDirectory = try baseDirectory ?? documentsDirectory()
        let inputURL = rootDirectory
            .appendingPathComponent("encrypted-bundles", isDirectory: true)
            .appendingPathComponent(request.assessmentId, isDirectory: true)
            .appendingPathComponent("bundle.exb", isDirectory: false)

        guard fileManager.fileExists(atPath: inputURL.path) else {
            throw DecryptBundleError("EXB file not found")
        }

        let exb = try Data(contentsOf: inputURL)
        let headerEnd = try readHeaderEnd(from: exb)
        let ciphertextEnd = exb.count - Self.authTagLength

        guard ciphertextEnd > headerEnd else {
            throw DecryptBundleError("Corrupted EXB payload")
        }

        let ciphertext = exb.subdata(in: headerEnd..<ciphertextEnd)
        let decrypted = try decryptPayload(request: request, ciphertext: ciphertext)

        let outputDirectory = rootDirectory
            .appendingPathComponent("encrypted-bundles", isDirectory: true)
            .appendingPathComponent(request.assessmentId, isDirectory: true)
            .appendingPathComponent("decrypted", isDirectory: true)
        let outputURL = outputDirectory.appendingPathComponent("bundle.zip", isDirectory: false)

        try fileManager.createDirectory(
            at: outputDirectory,
            withIntermediateDirectories: true,
            attributes: nil
        )
        try decrypted.write(to: outputURL, options: .atomic)

        return outputURL
    }

    private func decryptPayload(request: DecryptBundleRequest, ciphertext: Data) throws -> Data {
        let nonce = try AES.GCM.Nonce(data: request.iv)
        // The EXB file carries ciphertext only; the authentication tag is provided separately.
        let sealedBox = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: ciphertext,
            tag: request.tag
        )

        let key = SymmetricKey(data: request.cek)
        // AAD must match the producer exactly or authentication will fail.
        let aad = Data("\(request.examId)|\(request.sessionId)|bundle".utf8)
        let decrypted = try AES.GCM.open(sealedBox, using: key, authenticating: aad)

        return Data(decrypted)
    }

    private func readHeaderEnd(from exb: Data) throws -> Int {
        guard exb.count >= Self.headerPrefixLength else {
            throw DecryptBundleError("Invalid EXB format")
        }

        let magic = exb.prefix(4)
        guard magic.elementsEqual(Data("EXB1".utf8)) else {
            throw DecryptBundleError("Invalid EXB format")
        }

        // Bytes 4-7 store the EXB header length as little-endian UInt32.
        let headerLength = exb[4..<8].enumerated().reduce(0) { partialResult, element in
            partialResult | (Int(element.element) << (element.offset * 8))
        }
        let headerEnd = Self.headerPrefixLength + headerLength

        guard headerEnd < exb.count else {
            throw DecryptBundleError("Corrupted EXB header")
        }

        return headerEnd
    }

    private func documentsDirectory() throws -> URL {
        guard let directory = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else {
            throw DecryptBundleError("Unable to resolve documents directory")
        }
        return directory
    }

    private static let headerPrefixLength = 8
    private static let authTagLength = 16
}

struct DecryptBundleError: Error {
    let message: String

    init(_ message: String) {
        self.message = message
    }
}
