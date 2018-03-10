import java.lang.reflect.Array
import java.net.URI
import java.util.Optional

/**
 * "otpauth" URI encoder and decoder.
 *
 * @example {{{
 * // Random key generation
 * // Scala
 * OTPAuthURICodec.encode(
 * "totp",
 * "Account Name",
 * OTPKey.random(OTPAlgorithm.SHA1),
 * Some("Ejisan Kuro"),
 * Map())
 * // => otpauth://totp/Ejisan%20Kuro:Account%20Name?secret=WBVYNT2KUJQADJGK7DFUDGWUERFZN2YS&issuer=Ejisan%20Kuro
 *
 *
 *
 */
object OTPAuthURICodec {
    class Decoded(
        val protocol: String,
        val account: String,
        val otpkey: OTPKey,
        val issuer: Optional<String>,
        val params: Map<String, String>)

    /**
     * Encodes the parameters as "otpauth" [java.net.URI]
     */
    fun encode(
        protocol: String,
        account: String,
        otpkey: OTPKey,
        issuer: Optional<String>,
        params: Map<String, String>): URI {
        val label = issuer.map { i -> "/$i:$account" }.orElse("/$account")
        val p: Set<Pair<String, String>> = params.map { it.toPair() }.toSet()
                .plus(setOf(Pair("secret", otpkey.toBase32())))
                .plus(issuer.map { setOf(Pair("issuer", it))}.orElse(emptySet()))
        return URI("otpauth", protocol, label, p.map { p -> "${p.first}=${p.second}"}.joinToString { "&" }, null)
    }

    /**
     * Decodes the "otpauth" [java.net.URI]
     */
    fun decode(uri: URI): Optional<Decoded> {
        val scheme = uri.scheme.toLowerCase()
        val protocal = uri.host
        val params: Map<String, String> = uri.query.split('&').map { it.split('=', limit=2)}.mapNotNull { r ->
            Pair(r?.getOrElse(0, {""}), r?.getOrElse(1, {""}))
        }.toMap()
        val pair: Pair<String, Optional<String>> = uri.path.substring(1).split(":", limit=2)
                .let { r ->
                    Pair(r.getOrElse(1, {""}), Optional.ofNullable(r.getOrNull(0)))
                }
        if (scheme == "otpauth" && !params.keys.find { it == "secret" }.isNullOrEmpty()) {
            val otpkey = OTPKey.fromBase32(params.getValue("secret"))
            return Optional.of(Decoded(protocal, pair.first, otpkey, pair.second, params))
        } else return Optional.empty()
    }
}