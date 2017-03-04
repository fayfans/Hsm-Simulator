package tech.ffs.hsmsimulator

import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

object CipherUtils {
  private def zeroArray(n: Int) = Array.fill(n)(0.toByte)

  private val ZERO_GROUP = zeroArray(8)

  def xor(x: Array[Byte], y: Array[Byte]) = (x zip y) map { case (a, b) => (a ^ b).toByte }

  def tripleDes(key: Array[Byte], data: Array[Byte]) = {
    if (key.length != 16) throw new IllegalArgumentException("Wrong key size")
    val tdesKey = key ++ key.slice(0, 8)
    val cipher = Cipher.getInstance("DESede")
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(tdesKey, "DESede"))
    val lastGroupLength = data.length % 8
    val padding = if (lastGroupLength > 0) Array(0x80.toByte) ++ zeroArray(7 - lastGroupLength) else Array.emptyByteArray
    val paddedData = data ++ padding
    cipher.doFinal(paddedData).slice(0, paddedData.length)
  }

  def diversify(mk: Array[Byte], seed: Array[Byte]) = {
    if (mk.length != 16) throw new IllegalArgumentException("Wrong key size")
    if (seed.length != 8) throw new IllegalArgumentException("Wrong seed size")
    tripleDes(mk, seed) ++ tripleDes(mk, seed.map(a => (~a).toByte))
  }

  def mac(key: Array[Byte], iv: Array[Byte], data: Array[Byte]) = {
    if (key.length != 16) throw new IllegalArgumentException("Wrong key size")
    if (iv.length != 8) throw new IllegalArgumentException("Wrong iv size")
    val cipher = Cipher.getInstance("DES")
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.slice(0, 8), "DES"))
    val padding = Array(0x80.toByte) ++ zeroArray(7 - data.length % 8)
    val paddedGroups = (data ++ padding).grouped(8)
    val o = paddedGroups.foldLeft(xor(iv, paddedGroups.next()))((i, d) => xor(d, cipher.doFinal(i).slice(0, 8)))
    tripleDes(key, o).slice(0, 4)
  }

  def tac(key: Array[Byte], data: Array[Byte]) = {
    if (key.length != 8) throw new IllegalArgumentException("Wrong key size")
    val cipher = Cipher.getInstance("DES")
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"))
    val padding = Array(0x80.toByte) ++ zeroArray(7 - data.length % 8)
    (data ++ padding).grouped(8).foldLeft(ZERO_GROUP)((o, i) => cipher.doFinal(xor(o, i)).slice(0, 8)).slice(0, 4)
  }
}