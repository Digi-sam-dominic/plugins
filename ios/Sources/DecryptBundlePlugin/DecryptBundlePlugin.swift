import Foundation
import Capacitor
import CryptoKit
import ZIPFoundation

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
            let zipURL = try implementation.decrypt(request: request)
            let destDir = zipURL.deletingLastPathComponent()
            try DecryptBundleFileDecryptor.extractZipSecure(
                zipURL: zipURL,
                destinationDirectory: destDir,
                fileManager: .default
            )
            try DecryptBundleFileDecryptor.ensureAssessmentJsonAtRoot(
                destinationDirectory: destDir,
                fileManager: .default
            )
            let relativeDecryptedDir = "encrypted-bundles/\(request.assessmentId)/decrypted"

            call.resolve([
                "path": relativeDecryptedDir
            ])
        } catch let error as DecryptBundleError {
            call.reject(error.message)
        } catch {
            call.reject("Decrypt failed: \(error.localizedDescription)")
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

        let fileSize = try fileSizeBytes(at: inputURL)
        let input = try FileHandle(forReadingFrom: inputURL)
        defer { try? input.close() }

        let prefix = try readExactly(from: input, count: Self.headerPrefixLength)
        let headerLen = try Self.headerLength(from: prefix)
        let headerBytes = Self.headerPrefixLength + headerLen

        try input.seek(toOffset: UInt64(headerBytes))

        let cipherSize = fileSize - UInt64(headerBytes + Self.authTagLength)
        if cipherSize <= 0 {
            throw DecryptBundleError("Corrupted EXB payload")
        }

        // Ciphertext in EXB excludes trailing tag bytes; auth tag is supplied separately (same as Android Cipher).
        let ciphertext = try readExactly(from: input, count: Int(cipherSize))
        let aad = Data("\(request.examId)|\(request.sessionId)|bundle".utf8)

        let symmetricKey = SymmetricKey(data: request.cek)
        let nonce = try AES.GCM.Nonce(data: request.iv)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: request.tag)
        let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: aad)

        try plaintext.write(to: outputURL, options: .atomic)

        return outputURL
    }

    /// Expand decrypted ZIP on disk only (avoids bridging ~100MB+ into the WebView).
    static func extractZipSecure(zipURL: URL, destinationDirectory: URL, fileManager: FileManager) throws {
        guard let archive = Archive(url: zipURL, accessMode: .read) else {
            throw DecryptBundleError("Invalid or unreadable zip archive")
        }

        let canonicalDest = destinationDirectory.resolvingSymlinksInPath().standardizedFileURL.path
        let destPrefix = canonicalDest.hasSuffix("/") ? canonicalDest : canonicalDest + "/"

        for entry in archive {
            let outURL = destinationDirectory.appendingPathComponent(entry.path)
            let resolvedPath = outURL.resolvingSymlinksInPath().standardizedFileURL.path
            if !resolvedPath.hasPrefix(destPrefix) {
                throw DecryptBundleError("Illegal zip entry: \(entry.path)")
            }

            if entry.type == .directory {
                try fileManager.createDirectory(at: outURL, withIntermediateDirectories: true)
            } else {
                try fileManager.createDirectory(
                    at: outURL.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )
                if fileManager.fileExists(atPath: outURL.path) {
                    try fileManager.removeItem(at: outURL)
                }
                _ = try archive.extract(entry, to: outURL)
            }
        }
    }

    static func ensureAssessmentJsonAtRoot(destinationDirectory: URL, fileManager: FileManager) throws {
        let root = destinationDirectory.appendingPathComponent("assessment.json")
        if fileManager.fileExists(atPath: root.path) {
            return
        }

        guard let enumerator = fileManager.enumerator(
            at: destinationDirectory,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsPackageDescendants]
        ) else {
            throw DecryptBundleError("ZIP did not contain assessment.json")
        }

        while let item = enumerator.nextObject() as? URL {
            var isDir: ObjCBool = false
            guard fileManager.fileExists(atPath: item.path, isDirectory: &isDir), !isDir.boolValue else {
                continue
            }
            guard item.lastPathComponent == "assessment.json" else {
                continue
            }
            if fileManager.fileExists(atPath: root.path) {
                try fileManager.removeItem(at: root)
            }
            try fileManager.copyItem(at: item, to: root)
            return
        }

        throw DecryptBundleError("ZIP did not contain assessment.json")
    }

    private func readExactly(from handle: FileHandle, count: Int) throws -> Data {
        var data = Data()
        data.reserveCapacity(count)

        while data.count < count {
            let chunk = handle.readData(ofLength: count - data.count)
            if chunk.isEmpty {
                throw DecryptBundleError("Unexpected end of EXB payload")
            }
            data.append(chunk)
        }

        return data
    }

    private func fileSizeBytes(at url: URL) throws -> UInt64 {
        let values = try url.resourceValues(forKeys: [.fileSizeKey])
        if let size = values.fileSize {
            return UInt64(size)
        }

        let attributes = try fileManager.attributesOfItem(atPath: url.path)
        guard let size = attributes[.size] as? NSNumber else {
            throw DecryptBundleError("Unable to read EXB size")
        }

        return size.uint64Value
    }

    private func documentsDirectory() throws -> URL {
        guard let directory = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else {
            throw DecryptBundleError("Unable to resolve documents directory")
        }
        return directory
    }

    private static func headerLength(from prefix: Data) throws -> Int {
        guard prefix.count == headerPrefixLength else {
            throw DecryptBundleError("Invalid EXB format")
        }

        let magic = prefix.prefix(4)
        guard magic.elementsEqual(Data("EXB1".utf8)) else {
            throw DecryptBundleError("Invalid EXB format")
        }

        let headerLength =
            Int(prefix[4]) |
            Int(prefix[5]) << 8 |
            Int(prefix[6]) << 16 |
            Int(prefix[7]) << 24

        return headerLength
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
