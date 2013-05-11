import sbt._
import Keys._

object BuildSettings {
  val buildSettings = Defaults.defaultSettings ++ Seq(
	organization := "grayson",
	version := "0.0.1",
	scalaVersion := "2.10.0",
	scalacOptions ++= Seq(),
	libraryDependencies ++= Seq(
	  "org.ow2.asm" % "asm-all" % "4.1",
	  "org.clapper" %% "grizzled-slf4j" % "1.0.1"
	)
  )
}

object SRTBuild extends Build {
  import BuildSettings._

  lazy val root: Project = Project(
	"root",
	file("core"),
	settings = buildSettings
  ) aggregate(macros, core)

  lazy val macros: Project = Project(
	"macros",
	file("macros"),
	settings = buildSettings ++ Seq(
	  libraryDependencies <+= (scalaVersion)("org.scala-lang" % "scala-reflect" % _))
  )

  lazy val core: Project = Project(
	"core",
	file("core"),
	settings = buildSettings
  ) dependsOn(macros)
}