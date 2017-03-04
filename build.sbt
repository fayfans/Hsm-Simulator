name := "HsmSimulator"

version := "1.0"

scalaVersion := "2.12.1"

libraryDependencies := Seq(
  "com.typesafe.akka" %% "akka-actor" % "2.4.17",
  "ch.qos.logback" % "logback-classic" % "1.1.7",
  "com.typesafe.scala-logging" %% "scala-logging" % "3.5.0",
  "org.iq80.leveldb" % "leveldb" % "0.9"
)