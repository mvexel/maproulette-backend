/*
 * Copyright (C) 2020 MapRoulette contributors (see CONTRIBUTORS.md).
 * Licensed under the Apache License, Version 2.0 (see LICENSE).
 */

package org.maproulette.framework.util

import play.api.db.Database
import play.api.db.evolutions.Evolutions
import play.api.inject.guice.GuiceApplicationBuilder
import scala.util.Properties

/**
  * A little helper class to create and drop test tables
  *
  * @author mcuthbert
  */
trait TestDatabase {
  implicit val application = GuiceApplicationBuilder()
    .configure(
      "db.default.url" -> s"jdbc:postgresql://${Properties.envOrElse("MR_TEST_DB_HOST", "localhost")}:${Properties
        .envOrElse("MR_TEST_DB_PORT", "5432")}/${Properties.envOrElse("MR_TEST_DB_NAME", "mr_test")}",
      "db.default.username" -> s"${Properties.envOrElse("MR_TEST_DB_USER", "osm")}",
      "db.default.password" -> s"${Properties.envOrElse("MR_TEST_DB_PASSWORD", "osm")}",
      "db.default.logSql"   -> false,
      // The background pool copies db.default when the config is parsed, before these overrides.
      "db.background.url" -> s"jdbc:postgresql://${Properties.envOrElse("MR_TEST_DB_HOST", "localhost")}:${Properties
        .envOrElse("MR_TEST_DB_PORT", "5432")}/${Properties.envOrElse("MR_TEST_DB_NAME", "mr_test")}",
      "db.background.username"         -> s"${Properties.envOrElse("MR_TEST_DB_USER", "osm")}",
      "db.background.password"         -> s"${Properties.envOrElse("MR_TEST_DB_PASSWORD", "osm")}",
      "maproulette.osm.consumerKey"    -> "test",
      "maproulette.osm.consumerSecret" -> "test",
      "maproulette.bootstrap"          -> true
    )
    .build()
  implicit val database = this.application.injector.instanceOf(classOf[Database])

  def applyEvolutions(): Unit = {
    Evolutions.cleanupEvolutions(database)
    Evolutions.applyEvolutions(database)
  }

  def cleanupEvolutions(): Unit = Evolutions.cleanupEvolutions(database)
}
