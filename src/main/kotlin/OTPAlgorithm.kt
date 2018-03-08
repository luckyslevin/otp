
import java.util.Optional

/**
 * OTP Algorithm
 *
 * @param name the algorithm value that is used for otpauth URI
 * @param value the algorithm value that is used for Java `javax.crypto.Mac`
 */

sealed class OTPAlgorithm(
        val name: String,
        val value: String,
        val defaultKeyLength: Int,
        val strongKeyLength: Int) {
    override fun toString(): String =
            "OTPAgorithm(${name}, ${value}, ${defaultKeyLength}, ${strongKeyLength})"

    override fun hashCode(): Int {
        return 41 * (
                41 * (
                        41 * name.hashCode() + value.hashCode()) +
                        defaultKeyLength.hashCode()) +
                strongKeyLength.hashCode()
    }


    object MD5: OTPAlgorithm("MD5", "HmacMD5", 160, 160)
    object SHA1: OTPAlgorithm("SHA1", "HmacSHA1", 160, 200)
    object SHA256 : OTPAlgorithm("SHA256", "HmacSHA256", 240, 280)
    object SHA512 : OTPAlgorithm("SHA512", "HmacSHA512", 480, 520)

    companion object {

        /**
         * JAVA API: Returns MD5 algorithm.
         */
        fun getMD5(): OTPAlgorithm = MD5

        /**
         * JAVA API: Returns SHA1 algorithm.
         */
        fun getSHA1(): OTPAlgorithm = SHA1


        /**
         * JAVA API: Returns SHA256 algorithm.
         */
        fun getSHA256(): OTPAlgorithm = SHA256

        /**
         * JAVA API: Returns SHA512 algorithm.
         */
        fun getSHA512(): OTPAlgorithm = SHA512

        /**
         * Finds [[OTPAlgorithm]] by name.
         */
        fun find(name: String): OTPAlgorithm? {
            return when (name) {
                "MD5" -> MD5
                "SHA1"-> SHA1
                "SHA256" -> SHA256
                "SHA512" -> SHA512
                else -> null
            }
        }

        /**
         * JAVA API: Finds [[OTPAlgorithm]] by name.
         */
        fun getInstanceOptionally(name: String): Optional<OTPAlgorithm> =
                Optional.ofNullable(find(name))
    }
}
