import SwiftSSLCore

public struct X509Validity: Sendable, Hashable {
    public let notBefore: String
    public let notAfter: String
    private let notBeforeInstant: VerificationInstant
    private let notAfterInstant: VerificationInstant

    internal init(
        notBefore: String,
        notAfter: String,
        notBeforeInstant: VerificationInstant,
        notAfterInstant: VerificationInstant
    ) {
        self.notBefore = notBefore
        self.notAfter = notAfter
        self.notBeforeInstant = notBeforeInstant
        self.notAfterInstant = notAfterInstant
    }

    public func contains(_ instant: VerificationInstant) -> Bool {
        notBeforeInstant <= instant && instant <= notAfterInstant
    }

    internal static func decode(
        notBefore: Span<UInt8>,
        notAfter: Span<UInt8>
    ) throws(X509CertificateError) -> X509Validity {
        guard let first = decodeTime(notBefore), let second = decodeTime(notAfter),
              first.instant <= second.instant else {
            throw .invalidValidity
        }
        return X509Validity(
            notBefore: first.text,
            notAfter: second.text,
            notBeforeInstant: first.instant,
            notAfterInstant: second.instant
        )
    }

    private static func decodeTime(
        _ bytes: Span<UInt8>
    ) -> (text: String, instant: VerificationInstant)? {
        guard bytes.count == 13 || bytes.count == 15 else {
            return nil
        }
        guard bytes[bytes.count - 1] == 0x5A else {
            return nil
        }
        var digits = ContiguousArray<UInt8>()
        digits.reserveCapacity(bytes.count - 1)
        var index = 0
        while index < bytes.count {
            let byte = bytes[index]
            if index < bytes.count - 1 {
                guard byte >= 0x30 && byte <= 0x39 else {
                    return nil
                }
                digits.append(byte - 0x30)
            }
            index += 1
        }
        func number(_ offset: Int, _ count: Int) -> Int {
            var value = 0
            var index = 0
            while index < count {
                value = value * 10 + Int(digits[offset + index])
                index += 1
            }
            return value
        }
        let year: Int
        let monthOffset: Int
        if bytes.count == 13 {
            let shortYear = number(0, 2)
            year = shortYear >= 50 ? 1900 + shortYear : 2000 + shortYear
            monthOffset = 2
        } else {
            year = number(0, 4)
            monthOffset = 4
        }
        let month = number(monthOffset, 2)
        let day = number(monthOffset + 2, 2)
        let hour = number(monthOffset + 4, 2)
        let minute = number(monthOffset + 6, 2)
        let second = number(monthOffset + 8, 2)
        guard month >= 1, month <= 12,
              day >= 1, day <= daysInMonth(year: year, month: month),
              hour <= 23, minute <= 59, second <= 59 else {
            return nil
        }
        guard let instant = makeInstant(
            year: year,
            month: month,
            day: day,
            hour: hour,
            minute: minute,
            second: second
        ) else {
            return nil
        }
        var result = ContiguousArray<UInt8>()
        result.reserveCapacity(bytes.count)
        var byteIndex = 0
        while byteIndex < bytes.count {
            result.append(bytes[byteIndex])
            byteIndex += 1
        }
        return (String(decoding: result, as: UTF8.self), instant)
    }

    private static func daysInMonth(year: Int, month: Int) -> Int {
        switch month {
        case 2:
            return isLeapYear(year) ? 29 : 28
        case 4, 6, 9, 11:
            return 30
        default:
            return 31
        }
    }

    private static func isLeapYear(_ year: Int) -> Bool {
        year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
    }

    private static func makeInstant(
        year: Int,
        month: Int,
        day: Int,
        hour: Int,
        minute: Int,
        second: Int
    ) -> VerificationInstant? {
        var adjustedYear = year
        adjustedYear -= month <= 2 ? 1 : 0
        let era = adjustedYear >= 0 ? adjustedYear / 400 : (adjustedYear - 399) / 400
        let yearOfEra = adjustedYear - era * 400
        let monthIndex = month + (month > 2 ? -3 : 9)
        let dayOfYear = (153 * monthIndex + 2) / 5 + day - 1
        let dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear
        let days = era * 146_097 + dayOfEra - 719_468
        let (daySeconds, dayOverflow) = Int64(days).multipliedReportingOverflow(by: 86_400)
        guard !dayOverflow else { return nil }
        let (clockSeconds, clockOverflow) = Int64(hour * 3_600 + minute * 60 + second).addingReportingOverflow(daySeconds)
        guard !clockOverflow else { return nil }
        do {
            return try VerificationInstant(secondsSinceUnixEpoch: clockSeconds, nanoseconds: 0)
        } catch {
            return nil
        }
    }
}
