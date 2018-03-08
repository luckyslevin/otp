import java.util.Optional

/**
 * A HOTP Authenticator Implementation.
 *
 * @see [[https://tools.ietf.org/html/rfc4226 RFC 4226]]
 * @see [[HOTP$ HOTP Factory]]
 *
 * @param algorithm the hash function used to calculate the HMAC.
 * @param digits the number of digits to truncate.
 * @param otpkey the shared secret key as [[OTPKey]] instance.
 */

class HOTP(
    val algorithm: OTPAlgorithm,
    val digits: Int,
    val otpkey: OTPKey): HOTPSupport {

    /**
     * Generates a HOTP code for the given counter.
     *
     * @see [[https://tools.ietf.org/html/rfc4226#section-5.3 Generating an HOTP Value]]
     *
     * @param counter the moving factor.
     * @return A numeric String HOTP code in base 10.
     */

    fun generate(counter: Long): String =
        intToDigits(generateForCounter(algorithm, digits, otpkey, counter), digits)

    /**
     * Generates HOTP codes for the given counter.
     *
     * @see [[https://tools.ietf.org/html/rfc4226#section-5.3 Generating an HOTP Value]]
     *
     * @param counter the moving factor.
     * @param lookAheadWindow the number of window to look ahead.
     * @return A `Map[Long, String]` object that contains counter as a key
     *         and a numeric String HOTP code in base 10 as a value.
     */
    fun generate(counter: Long, lookAheadWindow: Int): Map<Long, String> =
        generateForCounter(algorithm, digits, otpkey, counter, lookAheadWindow)
                .mapValues { intToDigits(it.component2() , digits) }

    /**
     * Validates the given HOTP code for the given counter.
     *
     * @see [[https://tools.ietf.org/html/rfc4226#section-7.2 Validation of HOTP Values]]
     *
     * @param counter the moving factor.
     * @param code the numeric String HOTP code in base 10.
     * @return `true` if it's valid, `false` otherwise.
     */
    fun validate(counter: Long, code: String): Boolean =
            validateWithCounter(algorithm, digits, otpkey, counter, digitsToInt(code))

    /**
     * Validates the given HOTP code for the given counter.
     *
     * @param counter the moving factor.
     * @param lookAheadWindow the number of window to look ahead.
     * @param code the numeric String HOTP code in base 10.
     * @return `Some(gap)` as valid counter and the gap if it's valid, `None` otherwise.
     */
    fun validate(counter: Long, lookAheadWindow: Int, code: String): Optional<Long> =
        validateWithCounter(algorithm, digits, otpkey, counter, lookAheadWindow, digitsToInt(code))

}