package org.maproulette.auth.oauth

import anorm._
import java.nio.file.{Files, Paths}
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID
import java.util.concurrent.{Callable, CountDownLatch, Executors, TimeUnit}
import org.scalatestplus.play.PlaySpec
import play.api.db.Databases

/** Real PostgreSQL tests: opted in explicitly, each case uses a fresh schema on a disposable test DB.
  * No application bootstrap, legacy migrations or existing application tables are touched.
  */
class OAuthRepositorySpec extends PlaySpec {
  private val now = Instant.parse("2026-01-01T00:00:00Z")
  private def hash(value: String): String =
    MessageDigest
      .getInstance("SHA-256")
      .digest(value.getBytes("UTF-8"))
      .map(b => f"${b & 0xff}%02x")
      .mkString
  private def pair(label: String): TokenHashes =
    TokenHashes(
      hash(s"access-$label"),
      hash(s"refresh-$label"),
      now.plusSeconds(300),
      now.plusSeconds(3600)
    )
  private def pending(label: String): OAuthInteraction =
    OAuthInteraction(
      hash(s"interaction-$label"),
      hash(s"browser-$label"),
      "app-test",
      "org.example:/callback",
      "tasks:read",
      s"client-state-$label",
      "s256-challenge",
      now.plusSeconds(600)
    )

  private def withStore(test: (OAuthRepository, play.api.db.Database) => Unit): Unit = {
    val url = sys.env.getOrElse(
      "OAUTH_TEST_DATABASE_URL",
      cancel("Set OAUTH_TEST_DATABASE_URL to a disposable PostgreSQL database")
    )
    val username = sys.env.getOrElse("OAUTH_TEST_DATABASE_USER", "oauth_test")
    val password = sys.env.getOrElse("OAUTH_TEST_DATABASE_PASSWORD", "")
    val schema   = "oauth_test_" + UUID.randomUUID().toString.replace("-", "")
    val admin = Databases(
      "org.postgresql.Driver",
      url,
      config = Map("username" -> username, "password" -> password)
    )
    admin.withConnection { implicit c =>
      SQL(s"CREATE SCHEMA $schema").execute()
    }
    val separator = if (url.contains("?")) "&" else "?"
    val db = Databases(
      "org.postgresql.Driver",
      s"$url${separator}currentSchema=$schema",
      config = Map("username" -> username, "password" -> password)
    )
    try {
      db.withConnection { implicit c =>
        SQL("CREATE TABLE users(id bigint PRIMARY KEY)").execute()
        SQL("INSERT INTO users VALUES(1),(2)").executeUpdate()
        Seq("130").foreach { version =>
          val evolution =
            new String(
              Files.readAllBytes(Paths.get(s"conf/evolutions/default/$version.sql")),
              "UTF-8"
            )
          val ups = evolution.split("# --- !Ups")(1).split("# --- !Downs")(0)
          // Execute migration text as SQL, not Anorm named-parameter syntax (regex uses braces).
          scala.util.Using.resource(c.createStatement()) { statement =>
            ups
              .split(";;")
              .map(_.linesIterator.filterNot(_.trim.startsWith("--")).mkString("\n").trim)
              .filter(_.nonEmpty)
              .foreach(statement.execute)
          }
        }
      }
      test(new OAuthRepository(db), db)
    } finally {
      db.shutdown()
      // This generated schema was created above solely for this case, never an application schema.
      admin.withConnection { implicit c =>
        SQL(s"DROP SCHEMA $schema CASCADE").execute()
      }
      admin.shutdown()
    }
  }

  private def approved(
      store: OAuthRepository,
      label: String,
      user: Long = 1L
  ): (OAuthInteraction, String, OAuthGrant) = {
    val interaction = pending(label)
    val code        = hash(s"code-$label")
    store.createInteraction(interaction)
    store.claimLogin(interaction.idHash, interaction.browserHash, now).isDefined mustBe true
    store.completeLogin(interaction.idHash, interaction.browserHash, user, hash("csrf"), now) mustBe true
    val grant = store
      .approveInteraction(
        interaction.idHash,
        interaction.browserHash,
        hash("csrf"),
        code,
        s"family-$label",
        now.plusSeconds(60),
        now
      )
      .get
    (interaction, code, grant)
  }
  private def redeem(
      store: OAuthRepository,
      code: String,
      tokens: TokenHashes
  ): Option[OAuthGrant] =
    store.redeemCode(code, "app-test", "org.example:/callback", "s256-challenge", tokens, now)

  private def race[A](left: => A, right: => A): List[A] = {
    val executor = Executors.newFixedThreadPool(2)
    val start    = new CountDownLatch(1)
    try {
      val a = executor.submit(new Callable[A] { def call(): A = { start.await(); left }  })
      val b = executor.submit(new Callable[A] { def call(): A = { start.await(); right } })
      start.countDown()
      List(a.get(10, TimeUnit.SECONDS), b.get(10, TimeUnit.SECONDS))
    } finally executor.shutdownNow()
  }

  "OAuth PostgreSQL persistence" should {
    "bind browser callbacks, consent CSRF and verified user, and consume each interaction once" in withStore {
      (store, _) =>
        val value = pending("browser")
        store.createInteraction(value)
        store.getInteraction(value.idHash, hash("wrong-browser"), now) mustBe None
        store.claimLogin(value.idHash, hash("wrong-browser"), now) mustBe None
        store.completeLogin(value.idHash, value.browserHash, 1, hash("csrf"), now) mustBe false
        store.claimLogin(value.idHash, value.browserHash, now).isDefined mustBe true
        store.claimLogin(value.idHash, value.browserHash, now) mustBe None
        store.completeLogin(value.idHash, value.browserHash, 1, hash("csrf"), now) mustBe true
        store.completeLogin(value.idHash, value.browserHash, 2, hash("csrf"), now) mustBe false
        store.approveInteraction(
          value.idHash,
          value.browserHash,
          hash("wrong-csrf"),
          hash("code"),
          "family",
          now.plusSeconds(60),
          now
        ) mustBe None
        store.getInteraction(value.idHash, value.browserHash, now).get.userId mustBe Some(1L)
        store
          .declineInteraction(value.idHash, value.browserHash, hash("csrf"), now)
          .isDefined mustBe true
        store.getInteraction(value.idHash, value.browserHash, now) mustBe None
        store.approveInteraction(
          value.idHash,
          value.browserHash,
          hash("csrf"),
          hash("code"),
          "family",
          now.plusSeconds(60),
          now
        ) mustBe None
        val expired = pending("expired-browser")
        store.createInteraction(expired)
        store.claimLogin(expired.idHash, expired.browserHash, expired.expiresAt) mustBe None
    }

    "atomically redeem one code once and commit replay revocation under concurrency" in withStore {
      (store, db) =>
        val (_, code, _) = approved(store, "concurrent-code")
        val a            = pair("a"); val b = pair("b")
        val outcomes     = race(redeem(store, code, a), redeem(store, code, b))
        outcomes.count(_.isDefined) mustBe 1
        store.authenticate(a.accessHash, now) mustBe None
        store.authenticate(b.accessHash, now) mustBe None
        db.withConnection { implicit c =>
          SQL("SELECT COUNT(*) FROM oauth_access_tokens").as(SqlParser.scalar[Long].single) mustBe 1L
        }
    }

    "validate client redirect PKCE and expiry without burning a valid unconsumed code" in withStore {
      (store, _) =>
        val (_, code, _) = approved(store, "bindings")
        val tokens       = pair("bindings")
        store.redeemCode(
          code,
          "wrong-client",
          "org.example:/callback",
          "s256-challenge",
          tokens,
          now
        ) mustBe None
        store.redeemCode(code, "app-test", "org.evil:/callback", "s256-challenge", tokens, now) mustBe None
        store.redeemCode(
          code,
          "app-test",
          "org.example:/callback",
          "wrong-challenge",
          tokens,
          now
        ) mustBe None
        redeem(store, code, tokens).isDefined mustBe true
        store.authenticate(tokens.accessHash, now).get.userId mustBe 1L
        val (_, expiredCode, _) = approved(store, "expired-code")
        store.redeemCode(
          expiredCode,
          "app-test",
          "org.example:/callback",
          "s256-challenge",
          pair("expired-code"),
          now.plusSeconds(60)
        ) mustBe None
    }

    "rotate refresh tokens once and commit family revocation on concurrent replay" in withStore {
      (store, db) =>
        val (_, code, _) = approved(store, "refresh")
        val first        = pair("first")
        redeem(store, code, first).isDefined mustBe true
        val second = pair("second"); val third = pair("third")
        store.rotate(first.refreshHash, "wrong-client", second, now) mustBe None
        val outcomes = race(
          store.rotate(first.refreshHash, "app-test", second, now),
          store.rotate(first.refreshHash, "app-test", third, now)
        )
        outcomes.count(_.isDefined) mustBe 1
        List(first, second, third).foreach { value =>
          store.authenticate(value.accessHash, now) mustBe None
        }
        new OAuthRepository(db).findRefresh(second.refreshHash, now) mustBe None
        db.withConnection { implicit c =>
          SQL("SELECT COUNT(*) FROM oauth_refresh_tokens").as(SqlParser.scalar[Long].single) mustBe 2L
        }
    }

    "expire access and refresh tokens and revoke only the bound user and application family" in withStore {
      (store, _) =>
        val (_, code, _)      = approved(store, "revoke", 1L)
        val (_, otherCode, _) = approved(store, "other", 2L)
        val first             = pair("revoke"); val other = pair("other")
        redeem(store, code, first).isDefined mustBe true
        redeem(store, otherCode, other).isDefined mustBe true
        store.authenticate(first.accessHash, first.accessExpiresAt) mustBe None
        val laterPair = TokenHashes(
          hash("later-a"),
          hash("later-r"),
          now.plusSeconds(5000),
          now.plusSeconds(6000)
        )
        store.rotate(first.refreshHash, "app-test", laterPair, first.refreshExpiresAt) mustBe None
        store.revoke(first.refreshHash, "wrong-client", now)
        store.authenticate(first.accessHash, now).isDefined mustBe true
        store.revoke(first.refreshHash, "app-test", now)
        store.authenticate(first.accessHash, now) mustBe None
        store.rotate(first.refreshHash, "app-test", pair("after-revoke"), now) mustBe None
        store.authenticate(other.accessHash, now).get.userId mustBe 2L
    }

    "persist only credential hashes, reject unhashed issuance and survive repository recreation" in withStore {
      (store, db) =>
        val (_, code, expected) = approved(store, "hashed")
        val tokens              = pair("hashed")
        intercept[IllegalArgumentException] {
          redeem(store, code, tokens.copy(accessHash = "raw-secret"))
        }
        redeem(store, code, tokens) mustBe Some(expected)
        new OAuthRepository(db).authenticate(tokens.accessHash, now) mustBe Some(expected)
        db.withConnection { implicit c =>
          SQL("SELECT token_hash FROM oauth_access_tokens").as(
            SqlParser.str("token_hash").single
          ) mustBe hash("access-hashed")
          SQL("SELECT token_hash FROM oauth_refresh_tokens").as(
            SqlParser.str("token_hash").single
          ) mustBe hash("refresh-hashed")
          SQL("SELECT code_hash FROM oauth_codes").as(SqlParser.str("code_hash").single) mustBe hash(
            "code-hashed"
          )
        }
    }

    "retain consumed expired refresh tokens for replay detection against their active family" in withStore {
      (store, _) =>
        val (_, code, _) = approved(store, "expired-replay")
        val old          = pair("old")
        redeem(store, code, old).isDefined mustBe true
        val later = now.plusSeconds(3500)
        val current = TokenHashes(
          hash("current-a"),
          hash("current-r"),
          now.plusSeconds(5000),
          now.plusSeconds(6000)
        )
        store.rotate(old.refreshHash, "app-test", current, later).isDefined mustBe true
        val afterExpiry = now.plusSeconds(3601)
        store.findRefresh(old.refreshHash, afterExpiry).isDefined mustBe true
        val attempted = TokenHashes(
          hash("attempt-a"),
          hash("attempt-r"),
          now.plusSeconds(5001),
          now.plusSeconds(6001)
        )
        store.rotate(old.refreshHash, "app-test", attempted, afterExpiry) mustBe None
        store.authenticate(current.accessHash, afterExpiry) mustBe None
    }

    "roll back consumption if token issuance fails partway through the transaction" in withStore {
      (store, _) =>
        val (_, firstCode, _) = approved(store, "rollback-first")
        val initial           = pair("rollback-first")
        redeem(store, firstCode, initial).isDefined mustBe true
        val (_, secondCode, _) = approved(store, "rollback-second")
        val collision          = pair("rollback-second").copy(refreshHash = initial.refreshHash)
        intercept[java.sql.SQLException] { redeem(store, secondCode, collision) }
        store.authenticate(collision.accessHash, now) mustBe None
        redeem(store, secondCode, pair("rollback-fixed")).isDefined mustBe true
        val rotationCollision = pair("rotation-collision").copy(refreshHash = initial.refreshHash)
        intercept[java.sql.SQLException] {
          store.rotate(initial.refreshHash, "app-test", rotationCollision, now)
        }
        store.authenticate(rotationCollision.accessHash, now) mustBe None
        store
          .rotate(initial.refreshHash, "app-test", pair("rotation-fixed"), now)
          .isDefined mustBe true
    }
  }
}
