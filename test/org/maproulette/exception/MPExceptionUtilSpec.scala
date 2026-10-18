/*
 * Copyright (C) 2020 MapRoulette contributors (see CONTRIBUTORS.md).
 * Licensed under the Apache License, Version 2.0 (see LICENSE).
 */
package org.maproulette.exception

import org.maproulette.models.Lock
import org.scalatestplus.play.PlaySpec
import play.api.libs.json.{JsObject, Json}
import play.api.mvc.Result
import play.api.test.Helpers._

import scala.concurrent.Future

class MPExceptionUtilSpec extends PlaySpec {
  private def respond(e: Throwable): Future[Result] =
    Future.successful(MPExceptionUtil.manageException(e))

  "manageException" should {
    "keep the legacy body unchanged when no error code is set" in {
      val result = respond(new InvalidException("Invalid task status supplied."))
      status(result) mustBe BAD_REQUEST
      contentAsJson(result) mustBe Json.obj(
        "status"  -> "KO",
        "message" -> "Invalid task status supplied."
      )
    }

    "add the error code next to the legacy fields" in {
      val result = respond(
        new InvalidException("Invalid task status supplied.", Some(ErrorCodes.InvalidTransition))
      )
      status(result) mustBe BAD_REQUEST
      contentAsJson(result) mustBe Json.obj(
        "status"  -> "KO",
        "message" -> "Invalid task status supplied.",
        "error"   -> "invalid_transition"
      )
    }

    "code a forbidden lock refresh" in {
      val result = respond(
        new CodedIllegalAccessException("Lock on item 1 does not exist.", ErrorCodes.LockRequired)
      )
      status(result) mustBe FORBIDDEN
      (contentAsJson(result) \ "status").as[String] mustBe "Forbidden"
      (contentAsJson(result) \ "error").as[String] mustBe "lock_required"
    }

    "code a missing task" in {
      val result =
        respond(new NotFoundException("Task with 1 not found.", Some(ErrorCodes.NotFound)))
      status(result) mustBe NOT_FOUND
      (contentAsJson(result) \ "error").as[String] mustBe "not_found"
    }

    "leave plain IllegalAccessException bodies without an error code" in {
      val result = respond(new IllegalAccessException("Only super users can modify tags"))
      status(result) mustBe FORBIDDEN
      contentAsJson(result).as[JsObject].keys mustBe Set("status", "message")
    }

    "code a lock conflict" in {
      val lock   = Lock(None, 1, 7L, 3L, -1L, List(7L, 8L))
      val result = respond(new LockConflictException("User already holds a lock", lock))
      status(result) mustBe CONFLICT
      (contentAsJson(result) \ "lockedTaskId").as[Long] mustBe 7L
      (contentAsJson(result) \ "error").as[String] mustBe "locked_by_other"
    }
  }
}
