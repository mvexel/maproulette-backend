/*
 * Copyright (C) 2020 MapRoulette contributors (see CONTRIBUTORS.md).
 * Licensed under the Apache License, Version 2.0 (see LICENSE).
 */
package org.maproulette.exception

import org.maproulette.models.Lock

/**
  * Machine-readable error codes, emitted as the `error` field next to the legacy
  * `status`/`message` fields, so clients can branch on the cause without parsing messages.
  */
object ErrorCodes {
  val LockedByOther: String     = "locked_by_other"
  val LockRequired: String      = "lock_required"
  val InvalidTransition: String = "invalid_transition"
  val ChallengePaused: String   = "challenge_paused"
  val NotFound: String          = "not_found"
  val GuestNotAllowed: String   = "guest_not_allowed"
  val InvalidRequest: String    = "invalid_request"
  val TaskNotFixed: String      = "task_not_fixed"
  val NotTaskFixer: String      = "not_task_fixer"
  val ChangesetOpen: String     = "changeset_open"
  val ChangesetNotOwned: String = "changeset_not_owned"
  val ChangesetTooFar: String   = "changeset_out_of_window"
  val LinkDisabled: String      = "changeset_link_disabled"
}

/**
  * Mixed into exceptions that can carry a machine-readable error code.
  */
trait ErrorCoded {
  def errorCode: Option[String]
}

/**
  * IllegalAccessException (403) that carries a machine-readable error code.
  *
  * @param message The message to send with the exception
  * @param code    The machine-readable error code
  */
class CodedIllegalAccessException(message: String, code: String)
    extends IllegalAccessException(message)
    with ErrorCoded {
  override val errorCode: Option[String] = Some(code)
}

/**
  * Simple exception class extending exception, to handle invalid API calls. This allows us to pattern
  * match on the exception and if InvalidException is found we return a BadRequest instead of
  * an InternalServerError
  *
  * @param message The message to send with the exception
  */
class InvalidException(message: String, val errorCode: Option[String] = None)
    extends Exception(message)
    with ErrorCoded

/**
  * NotFoundException should be throw whenever we try to retrieve an object based on the object id
  * and find nothing
  *
  * @param message The message to send with the exception
  */
class NotFoundException(message: String, val errorCode: Option[String] = None)
    extends Exception(message)
    with ErrorCoded

/**
  * Exception for handling any exceptions related to locking of MapRoulette objects
  *
  * @param message The message to send with the exception
  */
class LockedException(message: String, val errorCode: Option[String] = None)
    extends Exception(message)
    with ErrorCoded

/**
  * Thrown when a user attempts to lock a task while already holding a lock on a
  * different task. Carries the user's existing lock so callers can surface enough
  * detail (which task/bundle is currently held) for a client to offer a
  * confirm-and-switch flow, retrying with force=true.
  *
  * @param message The message to send with the exception
  * @param conflictingLock The lock the user currently holds elsewhere
  */
class LockConflictException(message: String, val conflictingLock: Lock) extends Exception(message)

/**
  * Exception for handling the unique violations when trying to insert objects into the database
  *
  * @param message The message to send with the exception
  */
class UniqueViolationException(message: String) extends Exception(message)

/**
  * Exception for handling any conflicts found during changeset conflation
  *
  * @param message The message to send with the exception
  */
class ChangeConflictException(message: String) extends Exception(message)

/**
  * Exception for wrapping all other errors
  *
  * @param message The message to send with the exception
  */
class InternalServerException(message: String) extends Exception(message)
