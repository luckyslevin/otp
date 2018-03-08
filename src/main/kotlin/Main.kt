fun main(args : Array<String>) {
    val a: OTPAlgorithm  = OTPAlgorithm.getMD5()
    val b: OTPAlgorithm  = OTPAlgorithm.getMD5()
    println(a.equals(b))

    val c = OTPAlgorithm.find("MD5")
    println(c?.value)
    val d = OTPAlgorithm.getInstanceOptionally("MD5")
    d.map { x -> println(x.value) }
    println(OTPAlgorithm.MD5)

    val key = OTPKey.random(a)
    println(key)
}
