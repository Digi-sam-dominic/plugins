import Foundation

@objc public class DecryptBundle: NSObject {
    @objc public func echo(_ value: String) -> String {
        print(value)
        return value
    }
}
