enum SHA256ScalarKernel {
    @inline(__always)
    static func compress(
        state: inout SIMD8<UInt32>,
        initialSchedule: SIMD16<UInt32>
    ) {
        var w0 = initialSchedule[0]
        var w1 = initialSchedule[1]
        var w2 = initialSchedule[2]
        var w3 = initialSchedule[3]
        var w4 = initialSchedule[4]
        var w5 = initialSchedule[5]
        var w6 = initialSchedule[6]
        var w7 = initialSchedule[7]
        var w8 = initialSchedule[8]
        var w9 = initialSchedule[9]
        var w10 = initialSchedule[10]
        var w11 = initialSchedule[11]
        var w12 = initialSchedule[12]
        var w13 = initialSchedule[13]
        var w14 = initialSchedule[14]
        var w15 = initialSchedule[15]

        var a = state[0]
        var b = state[1]
        var c = state[2]
        var d = state[3]
        var e = state[4]
        var f = state[5]
        var g = state[6]
        var h = state[7]

        round(&a, &b, &c, &d, &e, &f, &g, &h, w0, 0x428A_2F98)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w1, 0x7137_4491)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w2, 0xB5C0_FBCF)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w3, 0xE9B5_DBA5)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w4, 0x3956_C25B)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w5, 0x59F1_11F1)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w6, 0x923F_82A4)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w7, 0xAB1C_5ED5)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w8, 0xD807_AA98)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w9, 0x1283_5B01)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w10, 0x2431_85BE)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w11, 0x550C_7DC3)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w12, 0x72BE_5D74)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w13, 0x80DE_B1FE)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w14, 0x9BDC_06A7)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w15, 0xC19B_F174)

        extend(&w0, w1, w9, w14)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w0, 0xE49B_69C1)
        extend(&w1, w2, w10, w15)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w1, 0xEFBE_4786)
        extend(&w2, w3, w11, w0)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w2, 0x0FC1_9DC6)
        extend(&w3, w4, w12, w1)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w3, 0x240C_A1CC)
        extend(&w4, w5, w13, w2)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w4, 0x2DE9_2C6F)
        extend(&w5, w6, w14, w3)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w5, 0x4A74_84AA)
        extend(&w6, w7, w15, w4)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w6, 0x5CB0_A9DC)
        extend(&w7, w8, w0, w5)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w7, 0x76F9_88DA)
        extend(&w8, w9, w1, w6)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w8, 0x983E_5152)
        extend(&w9, w10, w2, w7)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w9, 0xA831_C66D)
        extend(&w10, w11, w3, w8)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w10, 0xB003_27C8)
        extend(&w11, w12, w4, w9)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w11, 0xBF59_7FC7)
        extend(&w12, w13, w5, w10)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w12, 0xC6E0_0BF3)
        extend(&w13, w14, w6, w11)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w13, 0xD5A7_9147)
        extend(&w14, w15, w7, w12)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w14, 0x06CA_6351)
        extend(&w15, w0, w8, w13)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w15, 0x1429_2967)

        extend(&w0, w1, w9, w14)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w0, 0x27B7_0A85)
        extend(&w1, w2, w10, w15)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w1, 0x2E1B_2138)
        extend(&w2, w3, w11, w0)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w2, 0x4D2C_6DFC)
        extend(&w3, w4, w12, w1)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w3, 0x5338_0D13)
        extend(&w4, w5, w13, w2)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w4, 0x650A_7354)
        extend(&w5, w6, w14, w3)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w5, 0x766A_0ABB)
        extend(&w6, w7, w15, w4)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w6, 0x81C2_C92E)
        extend(&w7, w8, w0, w5)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w7, 0x9272_2C85)
        extend(&w8, w9, w1, w6)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w8, 0xA2BF_E8A1)
        extend(&w9, w10, w2, w7)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w9, 0xA81A_664B)
        extend(&w10, w11, w3, w8)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w10, 0xC24B_8B70)
        extend(&w11, w12, w4, w9)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w11, 0xC76C_51A3)
        extend(&w12, w13, w5, w10)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w12, 0xD192_E819)
        extend(&w13, w14, w6, w11)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w13, 0xD699_0624)
        extend(&w14, w15, w7, w12)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w14, 0xF40E_3585)
        extend(&w15, w0, w8, w13)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w15, 0x106A_A070)

        extend(&w0, w1, w9, w14)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w0, 0x19A4_C116)
        extend(&w1, w2, w10, w15)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w1, 0x1E37_6C08)
        extend(&w2, w3, w11, w0)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w2, 0x2748_774C)
        extend(&w3, w4, w12, w1)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w3, 0x34B0_BCB5)
        extend(&w4, w5, w13, w2)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w4, 0x391C_0CB3)
        extend(&w5, w6, w14, w3)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w5, 0x4ED8_AA4A)
        extend(&w6, w7, w15, w4)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w6, 0x5B9C_CA4F)
        extend(&w7, w8, w0, w5)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w7, 0x682E_6FF3)
        extend(&w8, w9, w1, w6)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w8, 0x748F_82EE)
        extend(&w9, w10, w2, w7)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w9, 0x78A5_636F)
        extend(&w10, w11, w3, w8)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w10, 0x84C8_7814)
        extend(&w11, w12, w4, w9)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w11, 0x8CC7_0208)
        extend(&w12, w13, w5, w10)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w12, 0x90BE_FFFA)
        extend(&w13, w14, w6, w11)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w13, 0xA450_6CEB)
        extend(&w14, w15, w7, w12)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w14, 0xBEF9_A3F7)
        extend(&w15, w0, w8, w13)
        round(&a, &b, &c, &d, &e, &f, &g, &h, w15, 0xC671_78F2)

        state[0] &+= a
        state[1] &+= b
        state[2] &+= c
        state[3] &+= d
        state[4] &+= e
        state[5] &+= f
        state[6] &+= g
        state[7] &+= h
    }

    @inline(__always)
    private static func extend(
        _ word: inout UInt32,
        _ wordMinus15: UInt32,
        _ wordMinus7: UInt32,
        _ wordMinus2: UInt32
    ) {
        word = word
            &+ smallSigma0(wordMinus15)
            &+ wordMinus7
            &+ smallSigma1(wordMinus2)
    }

    @inline(__always)
    private static func round(
        _ a: inout UInt32,
        _ b: inout UInt32,
        _ c: inout UInt32,
        _ d: inout UInt32,
        _ e: inout UInt32,
        _ f: inout UInt32,
        _ g: inout UInt32,
        _ h: inout UInt32,
        _ word: UInt32,
        _ constant: UInt32
    ) {
        let temporary1 = h
            &+ bigSigma1(e)
            &+ (g ^ (e & (f ^ g)))
            &+ constant
            &+ word
        let temporary2 = bigSigma0(a)
            &+ ((a & b) | (c & (a | b)))

        h = g
        g = f
        f = e
        e = d &+ temporary1
        d = c
        c = b
        b = a
        a = temporary1 &+ temporary2
    }

    @inline(__always)
    private static func smallSigma0(_ value: UInt32) -> UInt32 {
        rotateRight(value, by: 7)
            ^ rotateRight(value, by: 18)
            ^ (value >> 3)
    }

    @inline(__always)
    private static func smallSigma1(_ value: UInt32) -> UInt32 {
        rotateRight(value, by: 17)
            ^ rotateRight(value, by: 19)
            ^ (value >> 10)
    }

    @inline(__always)
    private static func bigSigma0(_ value: UInt32) -> UInt32 {
        rotateRight(value, by: 2)
            ^ rotateRight(value, by: 13)
            ^ rotateRight(value, by: 22)
    }

    @inline(__always)
    private static func bigSigma1(_ value: UInt32) -> UInt32 {
        rotateRight(value, by: 6)
            ^ rotateRight(value, by: 11)
            ^ rotateRight(value, by: 25)
    }

    @inline(__always)
    private static func rotateRight(_ value: UInt32, by count: UInt32) -> UInt32 {
        (value &>> count) | (value &<< (32 - count))
    }
}
