package tech.ffs.hsmsimulator

import java.net.InetSocketAddress

import akka.actor.{Actor, Props}
import akka.io.Tcp
import akka.pattern.ask
import akka.util.{ByteString, Timeout}
import com.typesafe.scalalogging.Logger
import tech.ffs.hsmsimulator.Hsm.Message

import scala.concurrent.duration._

class ConnectionHandler(remote: InetSocketAddress) extends Actor {

  implicit val timeout: Timeout = 5.seconds
  implicit val dispatcher = context.system.dispatcher

  import Tcp._

  val logger = Logger[ConnectionHandler]
  val hsm = context.system.actorSelection("/user/hsm")

  private def wrapData(data: String): ByteString = {
    val buffer = new Array[Byte](data.length + 2)
    buffer(0) = (data.length >> 8).toByte
    buffer(1) = (data.length & 0xFF).toByte
    data.getBytes().copyToArray(buffer, 2)
    ByteString(buffer)
  }


  def receive = {
    case Received(data) =>
      val buffer = data.asByteBuffer
      val len = buffer.getShort()
      val cmd = data.drop(2).utf8String
      if (len != cmd.length) {
        sender() ! Write(wrapData(""))
      } else {
        val that = sender()
        (hsm ? Message(cmd)).mapTo[String].map { resp =>
          that ! Write(wrapData(resp))
        }
      }

    case PeerClosed =>
      context stop self
      logger.info(s"On disconnect: $remote")
  }
}