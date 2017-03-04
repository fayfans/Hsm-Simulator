package tech.ffs.hsmsimulator

import java.net.InetSocketAddress

import akka.actor.{Actor, Props}
import akka.io.{IO, Tcp}
import com.typesafe.scalalogging.Logger

class Server extends Actor {

  import Tcp._
  import context.system

  val logger = Logger[Server]

  IO(Tcp) ! Bind(self, new InetSocketAddress("0.0.0.0", 8018))

  def receive = {
    case Bound(localAddress) =>
      logger.info(s"Listening: $localAddress")

    case CommandFailed(_) => context stop self

    case Connected(remote, _) =>
      val handler = context.actorOf(Props(classOf[ConnectionHandler], remote))
      val connection = sender()
      connection ! Register(handler)
      logger.info(s"On connect: $remote")
  }

}