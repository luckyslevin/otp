import java.util.Arrays
import java.util.Base64
import java.security.Key
import java.security.SecureRandom
import org.apache.commons.codec.binary.Base32
import org.apache.commons.codec.binary.Hex

/**
 * A representation of a HMAC-based OTP key.
 *
 * @param key the raw formated key.
 * @see <a href="https://tools.ietf.org/html/rfc4226#section-7.5">RFC4226 Section-7.5</a>
 */

class OTPKey (private val key: Key) {
    /**
     * Returns the java key instance.
     */
    fun get(): Key = key

    /**
     * Returns key as byte array.
     */
    fun toByteArray(): ByteArray = key.getEncoded()

    /**
     * Returns key as hex decimal.
     */
    fun toHex(): String =
            String((Hex()).encode(toByteArray()), java.nio.charset.StandardCharsets.UTF_8)

    /**
     * Returns base64 encoded key.
     */
    fun toBase64(): String =
            Base64.getEncoder().encodeToString(toByteArray())

    /**
     * Returns base64 without padding encoded key.
     */
    fun toBase64WithoutPadding(): String =
            Base64.getEncoder().withoutPadding().encodeToString(toByteArray())

    /**
     * Returns base64 URL-Safe encoded key.
     */
    fun toBase64URL(): String =
            Base64.getUrlEncoder().encodeToString(toByteArray())

    /**
     * Returns base64 URL-Safe without padding encoded key.
     */
    fun toBase64URLWithoutPadding(): String =
            Base64.getUrlEncoder().encodeToString(toByteArray())

    /**
     * Returns base32 encoded key.
     */
    fun toBase32(): String =
            Base32().encodeToString(toByteArray())

    /**
     * Returns base32 without padding encoded key.
     */
    fun toBase32WithoutPadding(): String =
            Base32().encodeToString(toByteArray()).replace("=", "")

    /**
     * Returns base32 HEX without padding encoded key.
     */
    fun toBase32HexWithoutPadding(): String =
            Base32(true).encodeToString(toByteArray()).replace("=", "")

    /**
     * The size of the length of this key byte.
     */
    fun byteLength(): Int = toByteArray().size

    /**
     * The size of the length of this key.
     */
    fun keyLength(): Int = byteLength() * 8

    override fun toString(): String = "OTPKey(${toBase32()})"

    override fun hashCode(): Int = Arrays.hashCode(toByteArray())

    companion object {

        /**
         * JAVA API: Creates new [[OTPKey]] instance.
         *
         * @param key the RAW format key
         * @param strict if true then enable strict key length validation as RFC 4226 requires,
         *               if false then disable strict key length validation that allows short key length as 80 bits.
         * @see https://tools.ietf.org/html/rfc4226#section-4
         */

        fun getInstance(key: Key, strict: Boolean = true): OTPKey {
            if (strict) {
                require(
                        key.getEncoded().size >= 16) {
                    "RFC 4226 requires key length of at least 128 bits and recommends key length of 160 bits. If you need to use lower key length disable strict mode."
                }
            } else {
                require(
                        key.getEncoded().size >= 10) {
                    "Key length must be at least 80 bits. RFC 4226 requires key length of at least 128 bits and recommends key length of 160 bits."
                }
            }

            require(key.getFormat().toUpperCase() == "RAW") {
                "Invalid Key format. It must be \"RAW\"."
            }
            return OTPKey(key)
        }


        /**
         * Creates new [[OTPKey]] instance without key length validation.
         *
         * @param key the RAW format key
         */
        @Deprecated("Use apply method with key length validation. Key length must be at least 80 bits. RFC 4226 requires key length of at least 128 bits and recommends key length of 160 bits.", ReplaceWith("0.0.1"))
        fun lenient(key: Key): OTPKey  {
            require(key.getFormat().toUpperCase() == "RAW") {
                "Invalid Key format. It must be \"RAW\"."
            }
            return OTPKey(key)
        }

        /**
         * Creates new [[OTPKey]] instance from byte array.
         */
        fun fromByteArray(bytes: ByteArray, strict: Boolean = true): OTPKey =
            getInstance( javax.crypto.spec.SecretKeySpec(bytes, "RAW"), strict)

        /**
         * Creates new [[OTPKey]] instance from hex decimal.
         */
        fun fromHex(hexDecimal: String, strict: Boolean = true): OTPKey =
            fromByteArray(Hex.decodeHex(hexDecimal.toCharArray()), strict)

        /**
         * Creates new [[OTPKey]] instance from base64 or base64 without padding encoded key.
         */
        fun fromBase64(base64: String, strict: Boolean = true): OTPKey =
            fromByteArray(Base64.getDecoder().decode(base64), strict)

        /**
         * Creates new [[OTPKey]] instance from base64 URL-Safe or base64 URL-Safe without padding encoded key.
         */
        fun fromBase64URL(base64Url: String, strict: Boolean = true): OTPKey =
            fromByteArray(Base64.getUrlDecoder().decode(base64Url), strict)

        /**
         * Creates new [[OTPKey]] instance from base32 or base32 without padding encoded key.
         */
        fun fromBase32(base32: String, strict: Boolean = true): OTPKey =
            fromByteArray(Base32().decode(base32), strict)

        /**
         * Creates new [[OTPKey]] instance from base32 Hex or base32 Hex without padding encoded key.
         */
        fun fromBase32Hex(base32Hex: String, strict: Boolean = true): OTPKey =
            fromByteArray(Base32(true).decode(base32Hex), strict)


        inline private fun defaultPRNG(): SecureRandom =
            SecureRandom.getInstance("NativePRNGNonBlocking", "SUN")

        /**
         * Generates random [[OTPKey]] instance.
         *
         * @param keyLength the key length
         * @param algorithm the algorithm
         * @param prng the random number generator
         */
        fun random(keyLength: Int, algorithm: OTPAlgorithm, strict: Boolean, prng: SecureRandom): OTPKey {
            val gen = javax.crypto.KeyGenerator.getInstance(algorithm.value)
            gen.init(keyLength, prng)
            return getInstance(gen.generateKey(), strict)
        }

        /**
         * Generates random [[OTPKey]] instance.
         *
         * @param keyLength the key length
         * @param algorithm the algorithm
         * @param strict
         */
        fun random(keyLength: Int, algorithm: OTPAlgorithm, strict: Boolean = true): OTPKey =
            random(keyLength, algorithm, strict, defaultPRNG())

        /**
         * Generates random [[OTPKey]] instance with default key length.
         *
         * @param algorithm the algorithm
         * @param prng the random number generator
         */
        fun random(algorithm: OTPAlgorithm, prng: SecureRandom): OTPKey =
            random(algorithm.defaultKeyLength, algorithm, false, prng)

        /**
         * Generates random [[OTPKey]] instance with default key length.
         */
        fun random(algorithm: OTPAlgorithm): OTPKey =
            random(algorithm, defaultPRNG())

        /**
         * Generates random [[OTPKey]] instance with stronger key length.
         *
         * @param algorithm the algorithm
         * @param prng the random number generator
         */
        fun randomStrong(algorithm: OTPAlgorithm, prng: SecureRandom): OTPKey =
            random(algorithm.strongKeyLength, algorithm, false, prng)

        /**
         * Generates random [[OTPKey]] instance with stronger key length.
         */
        fun randomStrong(algorithm: OTPAlgorithm): OTPKey =
            randomStrong(algorithm, defaultPRNG())

    }
}
