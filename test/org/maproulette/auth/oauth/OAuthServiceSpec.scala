package org.maproulette.auth.oauth

import akka.actor.ActorSystem
import com.typesafe.config.ConfigFactory
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import org.mockito.ArgumentMatchers.{any, anyString, eq => eqM}
import org.mockito.Mockito.{never, verify, when}
import org.scalatest.BeforeAndAfterAll
import org.scalatestplus.mockito.MockitoSugar
import org.scalatestplus.play.PlaySpec
import play.api.Configuration
import scala.concurrent.Await
import scala.concurrent.duration._

class OAuthServiceSpec extends PlaySpec with MockitoSugar with BeforeAndAfterAll {
  private val actorSystem = ActorSystem(
    "oauth-protocol-test",
    ConfigFactory.parseString("""
    oauth-provider-dispatcher {
      type = Dispatcher
      executor = "thread-pool-executor"
      thread-pool-executor.fixed-pool-size = 2
    }
  """)
  )
  private val settings = new OAuthSettings(
    Configuration(
      ConfigFactory.parseString(
        """
    oauthProvider {
      enabled = true
      callbackUri = "https://mr.example/oauth/callback"
      clients = [
        { id = "app", name = "Example", redirectUris = ["org.example.app:/callback"] },
        {
          id = "writer", name = "Writer", redirectUris = ["org.example.writer:/callback"],
          scopes = ["tasks:read", "tasks:write"]
        },
        { id = "other", name = "Other", redirectUris = ["org.example.other:/callback"] }
      ]
    }
  """
      )
    )
  )
  private val verifier = "a" * 43
  private val challenge = Base64.getUrlEncoder
    .withoutPadding()
    .encodeToString(
      MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII))
    )
  private val grant =
    OAuthGrant("family", 42L, "app", "tasks:read", "org.example.app:/callback", challenge)
  private def params = Map(
    "grant_type"    -> Seq("authorization_code"),
    "client_id"     -> Seq("app"),
    "redirect_uri"  -> Seq(grant.redirectUri),
    "code_verifier" -> Seq(verifier),
    "code"          -> Seq("code")
  )
  private def fixture(): (OAuthService, OAuthStore) = {
    val store = mock[OAuthStore]
    when(store.findCode(anyString(), any[Instant])).thenReturn(Some(grant))
    when(
      store.redeemCode(
        anyString(),
        anyString(),
        anyString(),
        anyString(),
        any[TokenHashes],
        any[Instant]
      )
    ).thenReturn(Some(grant))
    when(store.findRefresh(anyString(), any[Instant])).thenReturn(Some(grant))
    when(store.rotate(anyString(), anyString(), any[TokenHashes], any[Instant]))
      .thenReturn(Some(grant))
    (new OAuthService(store, settings, actorSystem), store)
  }
  override protected def afterAll(): Unit = {
    Await.result(actorSystem.terminate(), 5.seconds)
    super.afterAll()
  }

  "The OAuth grant adapter" should {
    "initialize disabled without requiring a new dispatcher in an existing deployment config" in {
      val legacySystem = ActorSystem(
        "disabled-oauth-test",
        ConfigFactory
          .parseString("akka.actor.provider=local")
          .withFallback(ConfigFactory.load().withoutPath("oauth-provider-dispatcher"))
      )
      try {
        legacySystem.settings.config.hasPath("oauth-provider-dispatcher") mustBe false
        val store    = mock[OAuthStore]
        val disabled = new OAuthSettings(Configuration.empty)
        val service  = new OAuthService(store, disabled, legacySystem)
        Await.result(service.authenticate("A" * 43), 5.seconds) mustBe None
        verify(store, never()).authenticate(anyString(), any[Instant])
      } finally Await.result(legacySystem.terminate(), 5.seconds)
    }

    "use the library PKCE engine and issue opaque credentials through atomic storage" in {
      val (service, store) = fixture()
      val response         = Await.result(service.exchange(params, false), 5.seconds).toOption.get
      response.accessToken.matches("[A-Za-z0-9_-]{43}") mustBe true
      response.refreshToken.get.matches("[A-Za-z0-9_-]{43}") mustBe true
      response.scope mustBe Some("tasks:read")
      response.accessToken must not be response.refreshToken.get
      verify(store).redeemCode(
        eqM(OAuthSecrets.hash("code")),
        eqM("app"),
        eqM(grant.redirectUri),
        eqM(challenge),
        any[TokenHashes],
        any[Instant]
      )
    }

    "reject incorrect PKCE, a different client, and mismatched redirects before issuing" in {
      Seq(
        params.updated("code_verifier", Seq("b" * 43)),
        params
          .updated("client_id", Seq("other"))
          .updated("redirect_uri", Seq("org.example.other:/callback")),
        params.updated("redirect_uri", Seq("org.example.app:/callback/extra")),
        params - "code_verifier"
      ).foreach { attempt =>
        val (service, store) = fixture()
        Await.result(service.exchange(attempt, false), 5.seconds).isLeft mustBe true
        verify(store, never()).redeemCode(
          anyString(),
          anyString(),
          anyString(),
          anyString(),
          any[TokenHashes],
          any[Instant]
        )
      }
    }

    "reject duplicates, client secrets, alternate grants and scope escalation" in {
      Seq(
        params.updated("client_id", Seq("app", "other")),
        params.updated("client_secret", Seq("embedded-secret")),
        params.updated("grant_type", Seq("password")),
        Map(
          "grant_type"    -> Seq("refresh_token"),
          "client_id"     -> Seq("app"),
          "refresh_token" -> Seq("refresh"),
          "scope"         -> Seq("tasks:write")
        )
      ).foreach { attempt =>
        val (service, store) = fixture()
        Await.result(service.exchange(attempt, false), 5.seconds).isLeft mustBe true
        verify(store, never()).redeemCode(
          anyString(),
          anyString(),
          anyString(),
          anyString(),
          any[TokenHashes],
          any[Instant]
        )
        verify(store, never()).rotate(anyString(), anyString(), any[TokenHashes], any[Instant])
      }
      val (service, _) = fixture()
      Await.result(service.exchange(params, true), 5.seconds).isLeft mustBe true
    }

    "delegate refresh to atomic rotation and convert committed replay failure to invalid_grant" in {
      val (service, store) = fixture()
      val refresh = Map(
        "grant_type"    -> Seq("refresh_token"),
        "client_id"     -> Seq("app"),
        "refresh_token" -> Seq("refresh")
      )
      Await.result(service.exchange(refresh, false), 5.seconds).isRight mustBe true
      verify(store).rotate(
        eqM(OAuthSecrets.hash("refresh")),
        eqM("app"),
        any[TokenHashes],
        any[Instant]
      )
      when(store.rotate(anyString(), anyString(), any[TokenHashes], any[Instant])).thenReturn(None)
      Await
        .result(service.exchange(refresh, false), 5.seconds)
        .left
        .toOption
        .get
        .errorType mustBe "invalid_grant"
    }

    "require exact redirects, explicit scope, state and S256 at authorization" in {
      val (service, _) = fixture()
      val valid = Map(
        "client_id"             -> Seq("app"),
        "redirect_uri"          -> Seq(grant.redirectUri),
        "response_type"         -> Seq("code"),
        "scope"                 -> Seq("tasks:read"),
        "state"                 -> Seq("native-state"),
        "code_challenge"        -> Seq(challenge),
        "code_challenge_method" -> Seq("S256")
      )
      service.authorization(valid).isRight mustBe true
      Seq(
        valid - "state",
        valid - "scope",
        valid.updated("code_challenge_method", Seq("plain")),
        valid.updated("redirect_uri", Seq(grant.redirectUri + "?redirect=evil"))
      ).foreach(attempt => service.authorization(attempt).isLeft mustBe true)
    }

    "grant tasks:write only to clients configured for it, storing a canonical scope" in {
      val (service, _) = fixture()
      def request(client: String, scope: String) = Map(
        "client_id"             -> Seq(client),
        "redirect_uri"          -> Seq(s"org.example.$client:/callback"),
        "response_type"         -> Seq("code"),
        "scope"                 -> Seq(scope),
        "state"                 -> Seq("native-state"),
        "code_challenge"        -> Seq(challenge),
        "code_challenge_method" -> Seq("S256")
      )
      service.authorization(request("writer", "tasks:write tasks:read")).toOption.get.scope mustBe
        "tasks:read tasks:write"
      service.authorization(request("writer", "tasks:read")).toOption.get.scope mustBe "tasks:read"
      service.authorization(request("app", "tasks:read")).toOption.get.scope mustBe "tasks:read"
      Seq(
        request("app", "tasks:read tasks:write"),
        request("writer", "tasks:write"),
        request("writer", "tasks:read tasks:read"),
        request("writer", "tasks:read tasks:admin")
      ).foreach(attempt =>
        service.authorization(attempt).left.toOption.get.errorType mustBe "invalid_scope"
      )
    }

    "never widen or narrow scope at refresh" in {
      val refresh = Map(
        "grant_type"    -> Seq("refresh_token"),
        "client_id"     -> Seq("app"),
        "refresh_token" -> Seq("refresh")
      )
      val (service, store) = fixture()
      Await
        .result(service.exchange(refresh.updated("scope", Seq("tasks:read")), false), 5.seconds)
        .toOption
        .get
        .scope mustBe Some("tasks:read")
      val widened = refresh.updated("scope", Seq("tasks:read tasks:write"))
      Await.result(service.exchange(widened, false), 5.seconds).left.toOption.get.errorType mustBe
        "invalid_scope"
      verify(store, org.mockito.Mockito.times(1))
        .rotate(anyString(), anyString(), any[TokenHashes], any[Instant])

      val writer                     = grant.copy(clientId = "writer", scope = "tasks:read tasks:write")
      val (writeService, writeStore) = fixture()
      when(writeStore.findRefresh(anyString(), any[Instant])).thenReturn(Some(writer))
      when(writeStore.rotate(anyString(), anyString(), any[TokenHashes], any[Instant]))
        .thenReturn(Some(writer))
      val writeRefresh = refresh.updated("client_id", Seq("writer"))
      Await
        .result(writeService.exchange(writeRefresh, false), 5.seconds)
        .toOption
        .get
        .scope mustBe Some("tasks:read tasks:write")
      Await
        .result(
          writeService.exchange(writeRefresh.updated("scope", Seq("tasks:read")), false),
          5.seconds
        )
        .left
        .toOption
        .get
        .errorType mustBe "invalid_scope"
    }

    "authenticate legacy read grants and write grants only while the client allows them" in {
      val (service, store) = fixture()
      when(store.authenticate(anyString(), any[Instant])).thenReturn(Some(grant))
      Await.result(service.authenticate(OAuthSecrets.generate()), 5.seconds) mustBe Some(grant)
      val writer = grant.copy(clientId = "writer", scope = "tasks:read tasks:write")
      when(store.authenticate(anyString(), any[Instant])).thenReturn(Some(writer))
      Await.result(service.authenticate(OAuthSecrets.generate()), 5.seconds) mustBe Some(writer)
      Seq(
        writer.copy(clientId = "app"),
        grant.copy(scope = "tasks:write"),
        grant.copy(scope = "unknown")
      ).foreach { value =>
        when(store.authenticate(anyString(), any[Instant])).thenReturn(Some(value))
        Await.result(service.authenticate(OAuthSecrets.generate()), 5.seconds) mustBe None
      }
    }

    "reject invalid client scope configuration" in {
      Seq(
        "[\"tasks:write\"]",
        "[\"tasks:read\", \"tasks:admin\"]",
        "[]",
        "[\"tasks:read\", \"tasks:unknown\"]"
      ).foreach { scopes =>
        an[Exception] must be thrownBy new OAuthSettings(
          Configuration(
            ConfigFactory.parseString(
              s"""oauthProvider { enabled = true, callbackUri = "https://mr.example/cb",
                 clients = [{ id = "x", name = "X", redirectUris = ["org.example.x:/cb"], scopes = $scopes }] }"""
            )
          )
        )
      }
    }

    "remain disabled by default and reject removed clients at bearer validation" in {
      new OAuthSettings(Configuration.empty).enabled mustBe false
      val (service, store) = fixture()
      when(store.authenticate(anyString(), any[Instant]))
        .thenReturn(Some(grant.copy(clientId = "removed")))
      Await.result(service.authenticate(OAuthSecrets.generate()), 5.seconds) mustBe None
    }
  }
}
