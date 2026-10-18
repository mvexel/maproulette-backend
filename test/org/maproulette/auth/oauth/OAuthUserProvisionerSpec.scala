package org.maproulette.auth.oauth

import anorm._
import java.util.UUID
import java.util.concurrent.{Callable, CountDownLatch, Executors, TimeUnit}
import java.util.concurrent.atomic.AtomicInteger
import org.joda.time.DateTime
import org.maproulette.framework.model.{Location, OSMProfile, User}
import org.maproulette.framework.service.UserService
import org.maproulette.utils.Crypto
import org.mockito.ArgumentMatchers._
import org.mockito.Mockito._
import org.mockito.stubbing.Answer
import org.scalatestplus.mockito.MockitoSugar
import org.scalatestplus.play.PlaySpec
import play.api.db.{Database, Databases}

/** Opt-in PostgreSQL regression coverage protecting legacy account credentials. */
class OAuthUserProvisionerSpec extends PlaySpec with MockitoSugar {
  private val date = DateTime.parse("2026-01-01T00:00:00Z")
  private val incoming = User(
    -1,
    date,
    date,
    OSMProfile(
      12345,
      "Updated OSM name",
      "updated description",
      "https://example.invalid/avatar",
      Location(40, -111),
      date,
      "upstream-token-must-not-persist"
    )
  )

  private def withDb(test: Database => Unit): Unit = {
    val url = sys.env.getOrElse(
      "OAUTH_TEST_DATABASE_URL",
      cancel("Set OAUTH_TEST_DATABASE_URL to a disposable PostgreSQL database with PostGIS")
    )
    val user     = sys.env.getOrElse("OAUTH_TEST_DATABASE_USER", "oauth_test")
    val password = sys.env.getOrElse("OAUTH_TEST_DATABASE_PASSWORD", "")
    val schema   = "oauth_user_test_" + UUID.randomUUID().toString.replace("-", "")
    val admin = Databases(
      "org.postgresql.Driver",
      url,
      config = Map("username" -> user, "password" -> password)
    )
    admin.withConnection { implicit c =>
      SQL(s"CREATE SCHEMA $schema").execute()
    }
    val separator = if (url.contains("?")) "&" else "?"
    val db = Databases(
      "org.postgresql.Driver",
      s"$url${separator}currentSchema=$schema,public",
      config = Map("username" -> user, "password" -> password)
    )
    try {
      db.withConnection { implicit c =>
        SQL(
          """CREATE TABLE users(id bigserial PRIMARY KEY,osm_id bigint NOT NULL UNIQUE,
          api_key text UNIQUE,osm_created timestamp NOT NULL,name text NOT NULL,description text,
          avatar_url text,oauth_token text NOT NULL,oauth_secret text NOT NULL,home_location geometry(Point,4326))"""
        ).execute()
      }
      test(db)
    } finally {
      db.shutdown()
      admin.withConnection { implicit c =>
        SQL(s"DROP SCHEMA $schema CASCADE").execute()
      }
      admin.shutdown()
    }
  }

  private def read(db: Database, osmId: Long): Option[User] = db.withConnection { implicit c =>
    SQL("SELECT * FROM users WHERE osm_id={osm}")
      .on("osm" -> osmId)
      .as(RowParser { row =>
        Success(
          incoming.copy(
            id = row[Long]("id"),
            apiKey = row[Option[String]]("api_key"),
            osmProfile = incoming.osmProfile
              .copy(displayName = row[String]("name"), requestToken = row[String]("oauth_token"))
          )
        )
      }.singleOpt)
  }
  private def seedLegacy(db: Database): Unit = db.withConnection { implicit c =>
    SQL("""INSERT INTO users(osm_id,api_key,osm_created,name,description,avatar_url,oauth_token,oauth_secret)
      VALUES(12345,'legacy-encrypted-api-key',CURRENT_TIMESTAMP,'Legacy name','Legacy description',
      'legacy-avatar','legacy-osm-token','legacy-osm-secret')""").executeUpdate()
    ()
  }
  private def legacyUnchanged(db: Database): Unit = db.withConnection { implicit c =>
    val row =
      SQL("SELECT * FROM users WHERE osm_id=12345").as(RowParser(row => Success(row)).single)
    row[String]("api_key") mustBe "legacy-encrypted-api-key"
    row[String]("oauth_token") mustBe "legacy-osm-token"
    row[String]("oauth_secret") mustBe "legacy-osm-secret"
    row[String]("name") mustBe "Legacy name"
    row[String]("description") mustBe "Legacy description"
    row[String]("avatar_url") mustBe "legacy-avatar"
  }
  private def crypto(): Crypto = {
    val result = mock[Crypto]
    when(result.encrypt(anyString())).thenAnswer(new Answer[String] {
      def answer(invocation: org.mockito.invocation.InvocationOnMock): String =
        "encrypted-" + invocation.getArgument[String](0)
    })
    result
  }
  private def service(db: Database): UserService = {
    val result = mock[UserService]
    when(result.retrieveByOSMId(anyLong())).thenAnswer(new Answer[Option[User]] {
      def answer(invocation: org.mockito.invocation.InvocationOnMock): Option[User] =
        read(db, invocation.getArgument[Long](0))
    })
    when(result.initializeHomeProject(any[User]())).thenAnswer(new Answer[User] {
      def answer(invocation: org.mockito.invocation.InvocationOnMock): User =
        invocation.getArgument[User](0)
    })
    result
  }

  "OAuth account provisioning" should {
    "leave existing users and their legacy credentials untouched" in withDb { db =>
      seedLegacy(db)
      val users    = service(db); val encryption = crypto()
      val resolved = new OAuthUserProvisioner(db, users, encryption).resolve(incoming)
      resolved.osmProfile.displayName mustBe "Legacy name"
      legacyUnchanged(db)
      verify(users, never()).initializeHomeProject(any[User]())
      verify(encryption, never()).encrypt(anyString())
    }

    "preserve a concurrent web login row inserted after its initial lookup" in withDb { db =>
      val users    = service(db)
      val lookedUp = new CountDownLatch(1); val inserted = new CountDownLatch(1)
      val calls    = new AtomicInteger(0)
      when(users.retrieveByOSMId(anyLong())).thenAnswer(new Answer[Option[User]] {
        def answer(invocation: org.mockito.invocation.InvocationOnMock): Option[User] = {
          if (calls.incrementAndGet() == 1) {
            lookedUp.countDown()
            require(inserted.await(10, TimeUnit.SECONDS))
            None
          } else read(db, invocation.getArgument[Long](0))
        }
      })
      val executor = Executors.newSingleThreadExecutor()
      try {
        val result = executor.submit(new Callable[User] {
          def call(): User = new OAuthUserProvisioner(db, users, crypto()).resolve(incoming)
        })
        lookedUp.await(10, TimeUnit.SECONDS) mustBe true
        seedLegacy(db)
        inserted.countDown()
        result.get(10, TimeUnit.SECONDS).osmProfile.displayName mustBe "Legacy name"
        legacyUnchanged(db)
        verify(users, never()).initializeHomeProject(any[User]())
      } finally {
        inserted.countDown(); executor.shutdownNow()
      }
    }

    "create one account and initialize once when two OAuth sign-ins race" in withDb { db =>
      val users        = service(db)
      val firstLookups = new CountDownLatch(2)
      val calls        = new AtomicInteger(0)
      when(users.retrieveByOSMId(anyLong())).thenAnswer(new Answer[Option[User]] {
        def answer(invocation: org.mockito.invocation.InvocationOnMock): Option[User] = {
          if (calls.incrementAndGet() <= 2) {
            firstLookups.countDown()
            require(firstLookups.await(10, TimeUnit.SECONDS))
            None
          } else read(db, invocation.getArgument[Long](0))
        }
      })
      val executor = Executors.newFixedThreadPool(2)
      try {
        val provisioner = new OAuthUserProvisioner(db, users, crypto())
        val a = executor.submit(new Callable[User] {
          def call(): User = provisioner.resolve(incoming)
        })
        val b = executor.submit(new Callable[User] {
          def call(): User = provisioner.resolve(incoming)
        })
        val first = a.get(10, TimeUnit.SECONDS); val second = b.get(10, TimeUnit.SECONDS)
        first.id mustBe second.id
        first.apiKey mustBe second.apiKey
        db.withConnection { implicit c =>
          SQL("SELECT COUNT(*) FROM users").as(SqlParser.scalar[Long].single) mustBe 1L
          val row = SQL("SELECT * FROM users").as(RowParser(row => Success(row)).single)
          row[String]("oauth_token") mustBe ""
          row[String]("oauth_secret") mustBe ""
          row[String]("api_key").startsWith("encrypted-") mustBe true
        }
        verify(users, times(1)).initializeHomeProject(any[User]())
      } finally executor.shutdownNow()
    }
  }
}
