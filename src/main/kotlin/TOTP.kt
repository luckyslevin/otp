import java.net.URI
import java.util.Optional

/**
 * A TOTP Authenticator Implementation.
 *
 * @see [[https://tools.ietf.org/html/rfc6238 RFC 6238]]
 * @see [[TOTP$ TOTP Factory]]
 *
 * @param algorithm the hash function used to calculate the HMAC.
 * @param digits the number of digits to truncate.
 * @param period the number of time steps.
 * @param initialTimestamp the initial counter Unix time.
 * @param otpkey the shared secret key as [[OTPKey]] instance.
 */
class TOTP(
    val algorithm: OTPAlgorithm,
    val digits: Int,
    val period: Int,
    val initialTimestamp: Long,
    val otpkey: OTPKey): TOTPSupport {

    /**
     * Returns current time that this generator uses.
     */
    fun currentTime(): Long = System.currentTimeMillis() / 1000

    /**
     * Returns remaining time that this generator uses.
     */
    fun countDown(): Long = period - (currentTime() % period)

    /**
     * Generates TOTP codes for the given instant of time.
     *
     * @param window the number of window to look around.
     * @return A `Map[Long, String]` object that contains counter as a key
     *         and a numeric String TOTP code in base 10 as a value.
     */
    fun generate(instantTimestamp: Long, window: Int): Map<Long, String> {
        return generateForTime(
                algorithm,
                digits,
                period,
                initialTimestamp,
                otpkey,
                instantTimestamp,
                window)
                .mapValues { intToDigits(it.component2() , digits) }
    }

    /**
     * Generates a TOTP code for the given instant of time.
     *
     * @see [[https://tools.ietf.org/html/rfc6238#section-4 TOTP Algorithm]]
     *
     * @param instantTimestamp the instant of time.
     * @return A numeric String TOTP code in base 10.
     */
    fun generate(instantTimestamp: Long): String  {
       return intToDigits(generateForTime(
                algorithm,
                digits,
                period,
                initialTimestamp,
                otpkey,
                instantTimestamp),
                digits)
    }

    /**
     * Generates a TOTP code for the current time.
     *
     * @see [[currentTime currentTime()]]
     * @see [[https://tools.ietf.org/html/rfc6238#section-4 TOTP Algorithm]]
     *
     * @return A numeric String TOTP code in base 10.
     */
    fun generate(): String = generate(currentTime())

    /**
     * Validates the given TOTP code for the given instant of time.
     *
     * @see [[currentTime currentTime()]]
     * @see [[https://tools.ietf.org/html/rfc6238#section-4 TOTP Algorithm]]
     * @see [[https://tools.ietf.org/html/rfc6238#section-5.2 Validation and Time-Step Size]]
     *
     * @param instantTimestamp the instant of time.
     * @return `true` if it's valid, `false` otherwise.
     */
    fun validate(instantTimestamp: Long, code: String): Boolean {
        return validateWithTime(
                algorithm,
                digits,
                period,
                initialTimestamp,
                otpkey,
                instantTimestamp,
                digitsToInt(code))
    }

    /**
     * Validates the given TOTP code for the instant of time.
     *
     * @param instantTimestamp the instant of time.
     * @param window the number of window to look around.
     * @param code the numeric String TOTP code in base 10.
     * @return `Some(gap)` as valid counter and the gap if it's valid, `None` otherwise.
     */
    fun validate(instantTimestamp: Long, window: Int, code: String): Optional<Long>  {
       return validateWithTime(
                algorithm,
                digits,
                period,
                initialTimestamp,
                otpkey,
                instantTimestamp,
                window,
                digitsToInt(code))
    }

    /**
     * Validates the given TOTP code for current time.
     *
     * @see [[currentTime currentTime()]]
     *
     * @param window the number of window to look around.
     * @return `Some(gap)` as valid counter and the gap if it's valid, `None` otherwise.
     */
    fun validate(window: Int, code: String): Optional<Long> = validate(currentTime(), window, code)


    /**
     * Validates the given TOTP code for current time.
     *
     * @see [[currentTime currentTime()]]
     * @see [[https://tools.ietf.org/html/rfc6238#section-4 TOTP Algorithm]]
     * @see [[https://tools.ietf.org/html/rfc6238#section-5.2 Validation and Time-Step Size]]
     *
     * @param code the numeric String TOTP code in base 10.
     * @return `true` if it's valid, `false` otherwise.
     */
    fun validate(code: String): Boolean = validate(currentTime(), code)

    /**
     * Returns a URI instance with TOTP configurations.
     *
     * @see [[https://github.com/google/google-authenticator/wiki/Key-Uri-Format Key URI Format]]
     *
     * @param account the account name of the subject.
     * @param issuer the service provider name.
     * @param params the additional parameters.
     */
    fun toURI(
        account: String,
        issuer: Optional<String> = Optional.empty(),
        params: Map<String, String> = emptyMap()): URI {
        val p = mapOf("digits" to digits.toString(),
            "period" to period.toString(),
            "algorithm" to algorithm.name)
        return OTPAuthURICodec.encode(
                protocol(),
                account,
                otpkey,
                issuer,
                params.plus(p))
    }

    override fun toString(): String =
        "TOTP(${otpkey.toBase32()}, ${algorithm.name}, $digits, $period, $initialTimestamp)"

    override fun hashCode(): Int {
        return 41 * (41 * (41 * (41 * otpkey.hashCode() + algorithm.hashCode()) +
                digits.hashCode()) + period.hashCode()) + initialTimestamp.hashCode()
    }

    companion object {
        /**
         * Java API: Creates new [[TOTP]] instance.
         */
        fun getInstance(
            algorithm: OTPAlgorithm,
            digits: Int,
            period: Int,
            initialTimestamp: Long,
            otpkey: OTPKey): TOTP =
            TOTP(algorithm, digits, period, initialTimestamp, otpkey)

        /**
         * Java API: Creates new [[TOTP]] instance.
         */
        fun getInstance(
            algorithm: OTPAlgorithm,
            digits: Int,
            period: Int,
            otpkey: OTPKey): TOTP =
            getInstance(algorithm, digits, period, 0L, otpkey)

        /**
         * Creates new [[TOTP]] instance from `otpauth` URI.
         *
         * @see [[https://github.com/google/google-authenticator/wiki/Key-Uri-Format Key URI Format]]
         */

        fun fromURI(uri: URI): TOTP {
            return OTPAuthURICodec.decode(uri).map { decoded ->
                val algo = decoded.params.get("algorithm")
                getInstance(algo?.let { OTPAlgorithm.getInstanceOptionally(it)
                        .orElse(OTPAlgorithm.getSHA1()) } ?: OTPAlgorithm.getSHA1(),
                        Optional.ofNullable(decoded.params.get("digits")).map { it.toInt() }.orElse(6),
                        Optional.ofNullable(decoded.params.get("period")).map { it.toInt() }.orElse(6),
                        decoded.otpkey)
            }.orElseThrow { throw IllegalArgumentException("Illegal URI given.") }
        }
    }
}
