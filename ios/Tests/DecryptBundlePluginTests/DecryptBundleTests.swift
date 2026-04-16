import XCTest
import CryptoKit
@testable import DecryptBundlePlugin

class DecryptBundleTests: XCTestCase {
    func testDecryptWritesBundleZip() throws {
        let fileManager = FileManager.default
        let decryptor = DecryptBundleFileDecryptor(fileManager: fileManager)
        let baseDirectory = fileManager.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try fileManager.createDirectory(
            at: baseDirectory,
            withIntermediateDirectories: true,
            attributes: nil
        )
        defer { try? fileManager.removeItem(at: baseDirectory) }

        let plaintext = Data("bundle payload".utf8)
        let cek = Data((0..<32).map { UInt8($0) })
        let iv = Data((1...12).map { UInt8($0) })
        let aad = Data("exam-1|session-9|bundle".utf8)
        let key = SymmetricKey(data: cek)
        let nonce = try AES.GCM.Nonce(data: iv)
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: aad)

        let exbHeader = Data("EXB1".utf8) + Data([0x02, 0x00, 0x00, 0x00]) + Data([0xaa, 0xbb])
        let exbData = exbHeader + sealed.ciphertext + Data(repeating: 0, count: 16)
        let assessmentDirectory = baseDirectory
            .appendingPathComponent("encrypted-bundles", isDirectory: true)
            .appendingPathComponent("assessment-42", isDirectory: true)
        try fileManager.createDirectory(
            at: assessmentDirectory,
            withIntermediateDirectories: true,
            attributes: nil
        )
        try exbData.write(to: assessmentDirectory.appendingPathComponent("bundle.exb"))

        let request = DecryptBundleRequest(
            assessmentId: "assessment-42",
            cek: cek,
            iv: iv,
            tag: sealed.tag,
            examId: "exam-1",
            sessionId: "session-9"
        )

        let outputURL = try decryptor.decrypt(request: request, baseDirectory: baseDirectory)
        let decrypted = try Data(contentsOf: outputURL)

        XCTAssertEqual(decrypted, plaintext)
    }
}
