import XCTest
import SSLCore
import SSLTypes

final class TLSTrafficSecretTests: XCTestCase {
    func testSecretIsBorrowedThroughCoreOwner() throws {
        let bytes: ContiguousArray<UInt8> = [1, 2, 3, 4]
        let secretBytes = try SecretBytes(copying: bytes.span)
        let owner = TLSTrafficSecret(
            endpoint: .client,
            algorithmIdentifier: 0x1301,
            secret: consume secretBytes
        )

        XCTAssertEqual(owner.endpoint, .client)
        XCTAssertEqual(owner.algorithmIdentifier, 0x1301)
        let borrowed = owner.withBorrowedSecret { span in
            var copy = ContiguousArray<UInt8>()
            copy.reserveCapacity(span.count)
            var index = 0
            while index < span.count {
                copy.append(span[index])
                index += 1
            }
            return copy
        }
        XCTAssertEqual(borrowed, bytes)
    }
}
