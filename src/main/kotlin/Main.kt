fun main(args : Array<String>) {
    val a: OTPAlgorithm  = OTPAlgorithm.getMD5()
    val b: OTPAlgorithm  = OTPAlgorithm.getMD5()
    println(a.equals(b))

    val c = OTPAlgorithm.find("MD5")
    println(c?.value)
    val d = OTPAlgorithm.getInstanceOptionally("MD5")
    d.map { x -> println(x.value) }
    val e = OTPAlgorithm.SHA1
    println(OTPAlgorithm.MD5)

    val key = OTPKey.random(e)
    println(key)

    val hotp = HOTP.getInstance(e, 6, key)
    println(hotp.generate(0, 10))

    val totp = TOTP.getInstance(e,6, 30, OTPKey.fromBase32("QPXVYHN67PRWGKOP7FBCIHBTGGDW2WIX"))
    println(totp)
    println(totp.generate())
    println(totp.countDown())
}
