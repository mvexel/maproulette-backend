package org.maproulette.auth.oauth

import anorm._
import java.sql.{Connection, Timestamp}
import java.time.Instant
import javax.inject.{Inject, Singleton}
import play.api.db.Database

/** Isolated persisted OAuth state. All credential inputs are SHA-256 hashes, never raw secrets.
  * Family locks serialize issuance, refresh rotation and revocation across server processes.
  * Invalid/replayed grants return normally from transactions so revocation is committed.
  */
@Singleton
class OAuthRepository @Inject() (db: Database) extends OAuthStore {
  private def stamp(value: Instant): Timestamp = Timestamp.from(value)
  private def digest(value: String): Unit =
    require(value.matches("[0-9a-f]{64}"), "Expected SHA-256 digest")
  private def interaction(row: Row): OAuthInteraction = OAuthInteraction(
    row[String]("interaction_hash"),
    row[String]("browser_hash"),
    row[String]("client_id"),
    row[String]("redirect_uri"),
    row[String]("scope"),
    row[String]("state"),
    row[String]("code_challenge"),
    row[java.util.Date]("expires_at").toInstant,
    row[Option[Long]]("user_id"),
    row[Option[String]]("csrf_hash")
  )
  private def grant(row: Row): OAuthGrant = OAuthGrant(
    row[String]("family_id"),
    row[Long]("user_id"),
    row[String]("client_id"),
    row[String]("scope"),
    row[String]("redirect_uri"),
    row[String]("code_challenge")
  )
  private def parser[A](read: Row => A): RowParser[A] = RowParser(row => Success(read(row)))

  override def createInteraction(value: OAuthInteraction): Unit = {
    digest(value.idHash); digest(value.browserHash); value.csrfHash.foreach(digest)
    // Only completeLogin may attach an authenticated upstream identity.
    require(value.userId.isEmpty && value.csrfHash.isEmpty)
    db.withConnection { implicit c =>
      SQL(
        """INSERT INTO oauth_interactions
        (interaction_hash,browser_hash,client_id,redirect_uri,scope,state,code_challenge,expires_at)
        VALUES ({id},{browser},{client},{redirect},{scope},{state},{challenge},{expires})"""
      ).on(
          "id"        -> value.idHash,
          "browser"   -> value.browserHash,
          "client"    -> value.clientId,
          "redirect"  -> value.redirectUri,
          "scope"     -> value.scope,
          "state"     -> value.clientState,
          "challenge" -> value.codeChallenge,
          "expires"   -> stamp(value.expiresAt)
        )
        .executeUpdate()
      ()
    }
  }

  override def getInteraction(
      idHash: String,
      browserHash: String,
      now: Instant
  ): Option[OAuthInteraction] =
    db.withConnection { implicit c =>
      SQL("""SELECT * FROM oauth_interactions WHERE interaction_hash={id}
        AND browser_hash={browser} AND expires_at>{now} AND consumed_at IS NULL""")
        .on("id" -> idHash, "browser" -> browserHash, "now" -> stamp(now))
        .as(parser(interaction).singleOpt)
    }

  override def claimLogin(
      idHash: String,
      browserHash: String,
      now: Instant
  ): Option[OAuthInteraction] =
    db.withTransaction { implicit c =>
      SQL("""UPDATE oauth_interactions SET login_claimed_at={now}
        WHERE interaction_hash={id} AND browser_hash={browser} AND expires_at>{now}
        AND consumed_at IS NULL AND login_claimed_at IS NULL AND user_id IS NULL RETURNING *""")
        .on("id" -> idHash, "browser" -> browserHash, "now" -> stamp(now))
        .as(parser(interaction).singleOpt)
    }

  override def completeLogin(
      idHash: String,
      browserHash: String,
      userId: Long,
      csrfHash: String,
      now: Instant
  ): Boolean = {
    digest(csrfHash)
    db.withTransaction { implicit c =>
      SQL("""UPDATE oauth_interactions SET user_id={user},csrf_hash={csrf}
        WHERE interaction_hash={id} AND browser_hash={browser} AND expires_at>{now}
        AND consumed_at IS NULL AND login_claimed_at IS NOT NULL AND user_id IS NULL""")
        .on(
          "id"      -> idHash,
          "browser" -> browserHash,
          "now"     -> stamp(now),
          "user"    -> userId,
          "csrf"    -> csrfHash
        )
        .executeUpdate() == 1
    }
  }

  private def consumeInteraction(
      idHash: String,
      browserHash: String,
      csrfHash: String,
      now: Instant
  )(implicit c: Connection): Option[OAuthInteraction] =
    SQL("""UPDATE oauth_interactions SET consumed_at={now}
      WHERE interaction_hash={id} AND browser_hash={browser} AND csrf_hash={csrf}
      AND user_id IS NOT NULL AND consumed_at IS NULL AND expires_at>{now} RETURNING *""")
      .on("id" -> idHash, "browser" -> browserHash, "csrf" -> csrfHash, "now" -> stamp(now))
      .as(parser(interaction).singleOpt)

  override def approveInteraction(
      idHash: String,
      browserHash: String,
      csrfHash: String,
      codeHash: String,
      familyId: String,
      codeExpiresAt: Instant,
      now: Instant
  ): Option[OAuthGrant] = {
    digest(codeHash)
    require(codeExpiresAt.isAfter(now))
    db.withTransaction { implicit c =>
      consumeInteraction(idHash, browserHash, csrfHash, now).flatMap { value =>
        SQL("""INSERT INTO oauth_families
          (family_id,user_id,client_id,scope,redirect_uri,code_challenge,created_at)
          VALUES ({family},{user},{client},{scope},{redirect},{challenge},{now})""")
          .on(
            "family"    -> familyId,
            "user"      -> value.userId.get,
            "client"    -> value.clientId,
            "scope"     -> value.scope,
            "redirect"  -> value.redirectUri,
            "challenge" -> value.codeChallenge,
            "now"       -> stamp(now)
          )
          .executeUpdate()
        SQL("""INSERT INTO oauth_codes(code_hash,family_id,expires_at)
          VALUES ({code},{family},{expires})""")
          .on("code" -> codeHash, "family" -> familyId, "expires" -> stamp(codeExpiresAt))
          .executeUpdate()
        Some(
          OAuthGrant(
            familyId,
            value.userId.get,
            value.clientId,
            value.scope,
            value.redirectUri,
            value.codeChallenge
          )
        )
      }
    }
  }

  override def declineInteraction(
      idHash: String,
      browserHash: String,
      csrfHash: String,
      now: Instant
  ): Option[OAuthInteraction] =
    db.withTransaction { implicit c =>
      consumeInteraction(idHash, browserHash, csrfHash, now)
    }

  // Fixed private table/column arguments only; all caller-controlled inputs are SQL parameters.
  private def find(
      table: String,
      hashColumn: String,
      hash: String,
      now: Instant,
      includeConsumed: Boolean = false
  ): Option[OAuthGrant] =
    db.withConnection { implicit c =>
      val active =
        if (includeConsumed) "(t.expires_at>{now} OR t.consumed_at IS NOT NULL)"
        else "t.expires_at>{now}"
      SQL(s"""SELECT f.* FROM $table t JOIN oauth_families f USING(family_id)
        WHERE t.$hashColumn={hash} AND $active AND f.revoked_at IS NULL""")
        .on("hash" -> hash, "now" -> stamp(now))
        .as(parser(grant).singleOpt)
    }
  override def findCode(codeHash: String, now: Instant): Option[OAuthGrant] =
    find("oauth_codes", "code_hash", codeHash, now, includeConsumed = true)
  override def findRefresh(refreshHash: String, now: Instant): Option[OAuthGrant] =
    find("oauth_refresh_tokens", "token_hash", refreshHash, now, includeConsumed = true)
  override def authenticate(accessHash: String, now: Instant): Option[OAuthGrant] =
    find("oauth_access_tokens", "token_hash", accessHash, now)

  private def lockFamily(table: String, hashColumn: String, hash: String)(
      implicit c: Connection
  ): Option[Row] =
    SQL(s"""SELECT f.* FROM oauth_families f
      WHERE family_id=(SELECT family_id FROM $table WHERE $hashColumn={hash}) FOR UPDATE""")
      .on("hash" -> hash)
      .as(parser(identity[Row]).singleOpt)

  private def revokeFamily(familyId: String, now: Instant)(implicit c: Connection): Unit = {
    SQL(
      "UPDATE oauth_families SET revoked_at=COALESCE(revoked_at,{now}) WHERE family_id={id}"
    ).on("now" -> stamp(now), "id" -> familyId)
      .executeUpdate()
    ()
  }
  private def issue(familyId: String, pair: TokenHashes)(implicit c: Connection): Unit = {
    SQL("""INSERT INTO oauth_access_tokens(token_hash,family_id,expires_at)
      VALUES ({hash},{family},{expires})""")
      .on("hash" -> pair.accessHash, "family" -> familyId, "expires" -> stamp(pair.accessExpiresAt))
      .executeUpdate()
    SQL("""INSERT INTO oauth_refresh_tokens(token_hash,family_id,expires_at)
      VALUES ({hash},{family},{expires})""")
      .on(
        "hash"    -> pair.refreshHash,
        "family"  -> familyId,
        "expires" -> stamp(pair.refreshExpiresAt)
      )
      .executeUpdate()
    ()
  }
  private def validatePair(pair: TokenHashes, now: Instant): Unit = {
    digest(pair.accessHash); digest(pair.refreshHash)
    require(pair.accessHash != pair.refreshHash)
    require(pair.accessExpiresAt.isAfter(now) && pair.refreshExpiresAt.isAfter(now))
  }

  override def redeemCode(
      codeHash: String,
      clientId: String,
      redirectUri: String,
      pkceChallenge: String,
      pair: TokenHashes,
      now: Instant
  ): Option[OAuthGrant] = {
    validatePair(pair, now)
    db.withTransaction { implicit c =>
      lockFamily("oauth_codes", "code_hash", codeHash).flatMap { family =>
        val value = grant(family)
        if (value.clientId != clientId || value.redirectUri != redirectUri ||
            value.codeChallenge != pkceChallenge || family[Option[java.util.Date]]("revoked_at").nonEmpty)
          None
        else {
          val code = SQL("SELECT * FROM oauth_codes WHERE code_hash={hash}")
            .on("hash" -> codeHash)
            .as(parser(identity[Row]).single)
          if (code[Option[java.util.Date]]("consumed_at").nonEmpty) {
            revokeFamily(value.familyId, now)
            None
          } else if (!code[java.util.Date]("expires_at").toInstant.isAfter(now)) None
          else {
            SQL("UPDATE oauth_codes SET consumed_at={now} WHERE code_hash={hash}")
              .on("hash" -> codeHash, "now" -> stamp(now))
              .executeUpdate()
            issue(value.familyId, pair)
            Some(value)
          }
        }
      }
    }
  }

  override def rotate(
      refreshHash: String,
      clientId: String,
      pair: TokenHashes,
      now: Instant
  ): Option[OAuthGrant] = {
    validatePair(pair, now)
    db.withTransaction { implicit c =>
      lockFamily("oauth_refresh_tokens", "token_hash", refreshHash).flatMap { family =>
        val value = grant(family)
        if (value.clientId != clientId || family[Option[java.util.Date]]("revoked_at").nonEmpty)
          None
        else {
          val token = SQL("SELECT * FROM oauth_refresh_tokens WHERE token_hash={hash}")
            .on("hash" -> refreshHash)
            .as(parser(identity[Row]).single)
          if (token[Option[java.util.Date]]("consumed_at").nonEmpty) {
            // Return rather than throw: rolling this transaction back would resurrect the family.
            revokeFamily(value.familyId, now)
            None
          } else if (!token[java.util.Date]("expires_at").toInstant.isAfter(now)) None
          else {
            SQL("UPDATE oauth_refresh_tokens SET consumed_at={now} WHERE token_hash={hash}")
              .on("hash" -> refreshHash, "now" -> stamp(now))
              .executeUpdate()
            issue(value.familyId, pair)
            Some(value)
          }
        }
      }
    }
  }

  override def revoke(tokenHash: String, clientId: String, now: Instant): Unit =
    db.withTransaction { implicit c =>
      val familyIds =
        SQL("""SELECT family_id FROM oauth_access_tokens WHERE token_hash={hash}
        UNION SELECT family_id FROM oauth_refresh_tokens WHERE token_hash={hash}""")
          .on("hash" -> tokenHash)
          .as(SqlParser.str("family_id").*)
      familyIds.sorted.foreach { familyId =>
        SQL("SELECT * FROM oauth_families WHERE family_id={id} FOR UPDATE")
          .on("id" -> familyId)
          .as(parser(identity[Row]).singleOpt)
          .filter(_[String]("client_id") == clientId)
          .foreach(_ => revokeFamily(familyId, now))
      }
    }
}
