
import java.util.Optional

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
        fun getMD5(): OTPAlgorithm = MD5
        fun getSHA1(): OTPAlgorithm = SHA1
        fun getSHA256(): OTPAlgorithm = SHA256
        fun getSHA512(): OTPAlgorithm = SHA512

        fun find(name: String): OTPAlgorithm? {
            return when (name) {
                "MD5" -> MD5
                "SHA1"-> SHA1
                "SHA256" -> SHA256
                "SHA512" -> SHA512
                else -> null
            }
        }

        fun getInstanceOptionally(name: String): Optional<OTPAlgorithm> =
                Optional.ofNullable(find(name))
    }
}
