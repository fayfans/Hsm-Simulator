package tech.ffs.hsmsimulator

import akka.actor.{ActorSystem, Props}

object Application extends App {
  override def main(args: Array[String]): Unit = {
    implicit val system = ActorSystem("hsm-simulator")
    implicit val executor = system.dispatcher

    system.actorOf(Props[Hsm], "hsm")
    system.actorOf(Props[Server])
  }
}
