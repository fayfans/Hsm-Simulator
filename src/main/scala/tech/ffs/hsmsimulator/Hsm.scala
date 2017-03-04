package tech.ffs.hsmsimulator

import java.io.File
import java.security.SecureRandom

import akka.actor.Actor
import com.typesafe.config.ConfigFactory
import org.iq80.leveldb.Options
import org.iq80.leveldb.impl.Iq80DBFactory.factory

object Hsm {

  case class Message(data: String)

}

class Hsm extends Actor {

  import Hsm._

  private val options = new Options()
  options.createIfMissing(true)
  private val db = factory.open(new File("db"), options)

  private val initCCK = db.get("cck".getBytes())
  private var cck = if (initCCK == null) "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" else new String(initCCK)
  private val initIK = db.get("ik".getBytes())
  private var ik = if (initIK == null) "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" else new String(initIK)

  private val conf = ConfigFactory.load()
  private val authCode = conf.getString("authcode")
  private val ACK = conf.getString("keys.ACK")
  private val ALK = conf.getString("keys.ALK")
  private val AUK = conf.getString("keys.AUK")
  private val AMK = conf.getString("keys.AMK")
  private val PUK = conf.getString("keys.PUK")
  private val PLK = conf.getString("keys.PLK")
  private val PK = conf.getString("keys.PK")
  private val TK = conf.getString("keys.TK")
  private val LK = conf.getString("keys.LK")
  private val DK = conf.getString("keys.DK")
  private val CK = conf.getString("keys.CK")
  private val MK = conf.getString("keys.MK")
  private val indexMap = Map(
    "00001" -> PK,
    "00002" -> ALK,
    "00003" -> TK,
    "00107" -> LK,
    "00109" -> PUK,
    "00110" -> PLK,
    "00301" -> CK,
    "00302" -> MK,
    "00303" -> ACK,
    "00305" -> AUK,
    "00306" -> AMK,
    "00401" -> DK
  )

  private def bytes2Hex(bytes: Array[Byte]) = bytes.map("%02X".format(_)).mkString

  private def hex2Bytes(hex: String) = hex.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray

  private val random = new SecureRandom()

  def receive = {
    case Message(cmd) =>
      if (cmd.startsWith("FC")) {
        if (cmd.substring(2) == authCode) {
          sender() ! "FD00"
        } else {
          sender() ! "FD17"
        }
      } else if (cmd.startsWith("FE")) {
        sender() ! "FF00"
      } else if (cmd.startsWith("F0")) {
        val newCCK = cmd.substring(2)
        if (newCCK.length != 32) {
          sender() ! "F117"
        } else {
          db.put("cck".getBytes(), newCCK.getBytes())
          cck = newCCK
          sender() ! "F100"
        }
      } else if (cmd.startsWith("F2")) {
        if (cmd.substring(2) != "00") {
          sender() ! "F317"
        } else {
          val buf = new Array[Byte](16)
          random.nextBytes(buf)
          ik = bytes2Hex(buf)
          sender() ! "F300"
        }
      } else if (cmd.startsWith("F4")) {
        if (cmd.substring(2) != "00000000") {
          sender() ! "F517"
        } else {
          val encryptedKey = CipherUtils.tripleDes(hex2Bytes(cck), hex2Bytes(ik + "8000000000000000"))
          val mac = CipherUtils.mac(hex2Bytes(cck), encryptedKey.slice(0, 8), encryptedKey.slice(8, encryptedKey.length))
          sender() ! "F500" + bytes2Hex(encryptedKey) + bytes2Hex(mac)
        }
      } else if (cmd.startsWith("58")) {
        if (cmd.substring(2, 7) != "00003") {
          sender() ! "5917"
        } else {
          val times = cmd(7).asDigit
          if (times > 1) {
            sender() ! "59FF"
          } else {
            val pan = hex2Bytes(cmd.substring(8, 24))
            val tac = cmd.substring(24, 32)
            val data = hex2Bytes(cmd.substring(51))
            val key = CipherUtils.diversify(hex2Bytes(TK), pan)
            val sessionKey = CipherUtils.xor(key.slice(0, 8), key.slice(8, 16))
            if (bytes2Hex(CipherUtils.tac(sessionKey, data)) == tac) {
              sender() ! "5900"
            } else {
              sender() ! "59FF"
            }
          }
        }
      } else if (cmd.startsWith("X3")) {
        if (cmd(2) != '0') {
          sender() ! "X417"
        } else {
          val index = cmd.substring(3, 8)
          val mk = hex2Bytes(indexMap(index))
          val times = cmd(8).asDigit
          if (index == "00401" && times == 1 || times == 2) {
            sender() ! "X417"
          } else {
            val key = if (times == 1) {
              val data = hex2Bytes(cmd.substring(9, 25))
              CipherUtils.diversify(mk, data)
            } else {
              val data1 = hex2Bytes(cmd.substring(9, 25))
              val data2 = hex2Bytes(cmd.substring(25, 31))
              CipherUtils.diversify(CipherUtils.diversify(mk, data1), data2)
            }
            val encryptedKey = CipherUtils.tripleDes(hex2Bytes(ik), key ++ hex2Bytes("8000000000000000"))
            val mac = CipherUtils.mac(hex2Bytes(ik), encryptedKey.slice(0, 8), encryptedKey.slice(8, encryptedKey.length))
            sender() ! "X4000024" + bytes2Hex(encryptedKey) + "0004" + bytes2Hex(mac)
          }
        }
      } else if (cmd.startsWith("EA")) {
        if (cmd.substring(2, 7) != "00107" || cmd(7).asDigit != 1) {
          sender() ! "EB17"
        } else {
          val asn = cmd.substring(8, 24)
          val datetime = cmd.substring(28, 42)
          val amount = cmd.substring(44, 52)
          val termId = cmd.substring(52, 64)
          val balance = cmd.substring(64, 72)
          val atc = cmd.substring(72, 76)
          val rand = cmd.substring(80, 88)
          val mac1 = cmd.substring(88, 96)

          val dlk = CipherUtils.diversify(hex2Bytes(LK), hex2Bytes(asn))
          val sessionKey = CipherUtils.tripleDes(dlk, hex2Bytes(rand + atc + "8000"))
          val genuineMac1 = CipherUtils.tac(sessionKey, hex2Bytes(balance + amount + "02" + termId))
          if (bytes2Hex(genuineMac1) == mac1) {
            val mac2 = CipherUtils.tac(sessionKey, hex2Bytes(amount + "02" + termId + datetime))
            sender() ! "EB000011" + datetime + bytes2Hex(mac2)
          } else {
            sender() ! "EBFF"
          }
        }
      } else if (cmd.startsWith("EB")) {
        val index = cmd.substring(2, 7)
        val mk = hex2Bytes(indexMap(index))
        val mode = cmd(7).asDigit
        if (cmd(8).asDigit != 1 || mode > 2) {
          sender() ! "ECFF"
        } else {
          val asn = hex2Bytes(cmd.substring(9, 25))
          val rndLen = cmd.substring(25, 29).toInt
          val rnd = cmd.substring(29, 29 + rndLen * 2)
          val len = cmd.substring(29 + rndLen * 2, 33 + rndLen * 2).toInt
          val data = cmd.substring(33 + rndLen * 2, 33 + (rndLen + len) * 2)
          val prefix = cmd.substring(37 + (rndLen + len) * 2)
          val key = CipherUtils.diversify(mk, asn)
          val secureMessage = if (mode == 2) {
            bytes2Hex(CipherUtils.tripleDes(key, hex2Bytes(f"${data.length / 2}%02X$data")))
          } else {
            data
          }
          val mac = CipherUtils.mac(key, hex2Bytes(vectorPadding(rnd)), hex2Bytes(prefix + secureMessage))
          sender() ! "EC00" + (if (mode == 2) f"${secureMessage.length / 2}%04d" + secureMessage else "") + bytes2Hex(mac)
        }
      } else if (cmd.startsWith("EC")) {
        val index = cmd.substring(2, 7)
        val mk = hex2Bytes(indexMap(index))
        if (cmd(7).asDigit != 1) {
          sender() ! "EDFF"
        } else {
          val asn = hex2Bytes(cmd.substring(8, 24))
          val key = CipherUtils.diversify(mk, asn)
          val len = cmd.substring(24, 28).toInt
          val data = cmd.substring(28, 28 + len * 2)
          val resp = CipherUtils.tripleDes(key, hex2Bytes(vectorPadding(data)))
          sender() ! "ED00" + f"${resp.length}%04d" + bytes2Hex(resp)
        }
      } else {
        sender() ! "FFFF"
      }
  }

  private def vectorPadding(iv: String): String = {
    val lastGroupLength = iv.length / 2 % 8
    val padding = if (lastGroupLength > 0) "00" * (8 - lastGroupLength) else ""
    iv + padding
  }
}
