import SSLCore

/// Foundation-free DER encoding of an absolute Unix timestamp for X.509 values.
public enum DERTimeEncoder {
    public static func encodeUnixTime(
        secondsSinceUnixEpoch seconds: Int64
    ) throws(DERWriteError) -> OwnedBytes {
        let components = components(secondsSinceUnixEpoch: seconds)
        let usesUTCTime = components.year >= 1950 && components.year <= 2049
        var content = ContiguousArray<UInt8>()
        content.reserveCapacity(usesUTCTime ? 13 : 15)
        if !usesUTCTime {
            appendTwoDigits(components.year / 100, to: &content)
        }
        appendTwoDigits(components.year, to: &content)
        appendTwoDigits(components.month, to: &content)
        appendTwoDigits(components.day, to: &content)
        appendTwoDigits(components.hour, to: &content)
        appendTwoDigits(components.minute, to: &content)
        appendTwoDigits(components.second, to: &content)
        content.append(0x5A)

        var writer = try DERWriter(
            maximumByteCount: content.count + 2,
            minimumCapacity: content.count + 2
        )
        try writer.append(
            tag: DERTag(
                tagClass: .universal,
                isConstructed: false,
                number: usesUTCTime ? 23 : 24
            ),
            content: content.span
        )
        return writer.finish()
    }

    private struct Components {
        let year: Int
        let month: Int
        let day: Int
        let hour: Int
        let minute: Int
        let second: Int
    }

    private static func components(
        secondsSinceUnixEpoch seconds: Int64
    ) -> Components {
        let secondsPerDay: Int64 = 86_400
        var days = seconds / secondsPerDay
        var remainder = seconds % secondsPerDay
        if remainder < 0 {
            remainder += secondsPerDay
            days -= 1
        }

        let shiftedDays = days + 719_468
        let era = (shiftedDays >= 0 ? shiftedDays : shiftedDays - 146_096) / 146_097
        let dayOfEra = shiftedDays - era * 146_097
        let yearOfEra = (
            dayOfEra - dayOfEra / 1_460 + dayOfEra / 36_524 - dayOfEra / 146_096
        ) / 365
        let provisionalYear = yearOfEra + era * 400
        let dayOfYear = dayOfEra - (
            365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100
        )
        let monthPrime = (5 * dayOfYear + 2) / 153
        let day = dayOfYear - (153 * monthPrime + 2) / 5 + 1
        let month = monthPrime < 10 ? monthPrime + 3 : monthPrime - 9
        let year = month <= 2 ? provisionalYear + 1 : provisionalYear

        return Components(
            year: Int(year),
            month: Int(month),
            day: Int(day),
            hour: Int(remainder / 3_600),
            minute: Int((remainder % 3_600) / 60),
            second: Int(remainder % 60)
        )
    }

    private static func appendTwoDigits(
        _ value: Int,
        to output: inout ContiguousArray<UInt8>
    ) {
        let reduced = value % 100
        output.append(UInt8(48 + reduced / 10))
        output.append(UInt8(48 + reduced % 10))
    }
}
