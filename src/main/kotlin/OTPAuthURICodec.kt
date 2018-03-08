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
//        val params = uri.query.split('&').map { it.split('=', 2)}
        return Optional.of(Decoded(protocol="", account="", otpkey="", issuer="", params=""))
    }
//        val scheme = uri.getScheme.toLowerCase
//        val protocol = uri.getHost
//        val params = uri.getQuery.split('&').map(_.split("=", 2)).collect {
//            case Array(key, value) => (key, value)
//            case Array(key) => (key, "")
//        }.toMap
//        val (account, issuer) = {
//            uri.getPath.substring(1).split(":", 2) match {
//                case Array(issuer, account) => (account, Some(issuer))
//                case Array(account) => (account, None)
//            }
//        }
//        if (scheme == "otpauth" && params.keys.exists(_ == "secret")) {
//            val otpkey = OTPKey.fromBase32(params("secret"))
//            Some(Decoded(protocol, account, otpkey, issuer, params))
//        } else None



}