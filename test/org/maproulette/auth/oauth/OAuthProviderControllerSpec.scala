package org.maproulette.auth.oauth

import akka.actor.ActorSystem
import akka.stream.{Materializer, SystemMaterializer}
import com.typesafe.config.ConfigFactory
import controllers.OAuthProviderController
import java.time.Instant
import org.maproulette.Config
import org.maproulette.framework.model.User
import org.maproulette.framework.service.UserService
import org.mockito.ArgumentMatchers.{any, anyLong, anyString}
import org.mockito.Mockito.{never, verify, when}
import org.scalatest.BeforeAndAfterAll
import org.scalatestplus.mockito.MockitoSugar
import org.scalatestplus.play.PlaySpec
import play.api.Configuration
import play.api.libs.json.Json
import play.api.libs.ws.{WSClient, WSRequest, WSResponse}
import play.api.mvc.Cookie
import play.api.test.FakeRequest
import play.api.test.Helpers._
import scala.concurrent.{Await, ExecutionContext, Future}
import scala.concurrent.duration._

class OAuthProviderControllerSpec extends PlaySpec with MockitoSugar with BeforeAndAfterAll {
  private val system = ActorSystem(
    "oauth-controller-test",
    ConfigFactory.parseString("""
    oauth-provider-dispatcher {
      type=Dispatcher
      executor="thread-pool-executor"
      thread-pool-executor.fixed-pool-size=2
    }
  """)
  )
  private implicit val ec: ExecutionContext       = system.dispatcher
  private implicit val materializer: Materializer = SystemMaterializer(system).materializer
  private val providerConfig = Configuration(
    ConfigFactory.parseString(
      """
    oauthProvider {
      enabled=true
      callbackUri="https://mr.example/oauth/callback"
      clients=[{
        id="app",name="Example <App>",redirectUris=["org.example.app:/callback"],
        scopes=["tasks:read","tasks:write"]
      }]
    }
  """
    )
  )
  private implicit val configuration: Configuration = Configuration.from(
    Map(
      Config.KEY_OSM_SERVER            -> "https://osm.example",
      Config.KEY_OSM_USER_DETAILS_URL  -> "/api/0.6/user/details",
      Config.KEY_OSM_REQUEST_TOKEN_URL -> "/oauth/request_token",
      Config.KEY_OSM_ACCESS_TOKEN_URL  -> "/oauth/access_token",
      Config.KEY_OSM_AUTHORIZATION_URL -> "/oauth/authorize",
      Config.KEY_OSM_CONSUMER_KEY      -> "test-client",
      Config.KEY_OSM_CONSUMER_SECRET   -> "test-secret",
      Config.KEY_OSM_OAUTH2_SCOPE      -> "read_prefs"
    )
  )
  private val state   = OAuthSecrets.generate()
  private val browser = OAuthSecrets.generate()
  private val csrf    = OAuthSecrets.generate()
  private val interaction = OAuthInteraction(
    OAuthSecrets.hash(state),
    OAuthSecrets.hash(browser),
    "app",
    "org.example.app:/callback",
    "tasks:read",
    "native-state",
    "a" * 43,
    Instant.now().plusSeconds(600),
    Some(42L),
    Some(OAuthSecrets.hash(csrf))
  )
  private val grant = OAuthGrant(
    "family",
    42L,
    "app",
    "tasks:read",
    interaction.redirectUri,
    interaction.codeChallenge
  )
  private val user = User.superUser.copy(
    id = 42L,
    guest = false,
    apiKey = Some("private-global-key"),
    osmProfile = User.superUser.osmProfile
      .copy(id = 99L, displayName = "Example User", requestToken = "private-osm-token")
  )

  private class Fixture(enabled: Boolean = true, config: Option[Configuration] = None) {
    val store = mock[OAuthStore]
    val settings = new OAuthSettings(
      config.getOrElse(if (enabled) providerConfig else Configuration.empty)
    )
    val service  = new OAuthService(store, settings, system)
    val identity = mock[OAuthOSMIdentity]
    val users    = mock[UserService]
    val ws       = mock[WSClient]
    val upstream = mock[WSRequest]
    val response = mock[WSResponse]
    when(ws.url(anyString())).thenReturn(upstream)
    when(upstream.withFollowRedirects(false)).thenReturn(upstream)
    when(upstream.withRequestTimeout(any[Duration])).thenReturn(upstream)
    when(upstream.withHttpHeaders(any[(String, String)])).thenReturn(upstream)
    when(upstream.post(any[Map[String, String]])(any())).thenReturn(Future.successful(response))
    when(response.status).thenReturn(200)
    when(response.json).thenReturn(
      Json.obj("access_token" -> "upstream-only-secret", "scope" -> "read_prefs")
    )
    when(identity.resolve(anyString())).thenReturn(Future.successful(user))
    val controller = new OAuthProviderController(
      stubControllerComponents(),
      service,
      settings,
      identity,
      users,
      new Config(),
      ws
    )
  }
  override protected def afterAll(): Unit = {
    Await.result(system.terminate(), 5.seconds)
    super.afterAll()
  }

  "OAuth authorization HTTP flow" should {
    "be inert by default" in {
      val f      = new Fixture(false)
      val result = f.controller.authorize.apply(FakeRequest(GET, "/oauth/authorize"))
      status(result) mustBe NOT_FOUND
      verify(f.store, never()).createInteraction(any[OAuthInteraction])
    }

    "bind upstream callback to persisted state and browser before contacting OSM" in {
      val f = new Fixture()
      when(f.store.claimLogin(anyString(), anyString(), any[Instant])).thenReturn(None)
      val result = f.controller.callback.apply(
        FakeRequest(GET, s"/oauth/callback?state=$state&code=example")
          .withCookies(Cookie("mr_oauth", browser))
      )
      status(result) mustBe BAD_REQUEST
      verify(f.ws, never()).url(anyString())
      val noCookie = f.controller.callback
        .apply(FakeRequest(GET, s"/oauth/callback?state=$state&code=example"))
      status(noCookie) mustBe BAD_REQUEST
    }

    "exchange upstream identity server-side and show escaped consent without leaking credentials" in {
      val f = new Fixture()
      when(f.store.claimLogin(anyString(), anyString(), any[Instant])).thenReturn(Some(interaction))
      when(f.store.completeLogin(anyString(), anyString(), anyLong(), anyString(), any[Instant]))
        .thenReturn(true)
      val result = f.controller.callback.apply(
        FakeRequest(GET, s"/oauth/callback?state=$state&code=example")
          .withCookies(Cookie("mr_oauth", browser))
      )
      status(result) mustBe OK
      val body = contentAsString(result)
      body must include("Example &lt;App&gt;")
      body must include("name=\"csrf\"")
      body must not include "upstream-only-secret"
      body must not include "private-global-key"
      body must not include "private-osm-token"
      header("Cache-Control", result) mustBe Some("no-store")
      header("Content-Security-Policy", result).get must include("org.example.app:")
      verify(f.upstream).withFollowRedirects(false)
      verify(f.identity).resolve("upstream-only-secret")
    }

    "name the write permission on consent only for a tasks:write request" in {
      Seq(
        "tasks:read"             -> false,
        "tasks:read tasks:write" -> true
      ).foreach {
        case (scope, write) =>
          val f = new Fixture()
          when(f.store.claimLogin(anyString(), anyString(), any[Instant]))
            .thenReturn(Some(interaction.copy(scope = scope)))
          when(
            f.store.completeLogin(anyString(), anyString(), anyLong(), anyString(), any[Instant])
          ).thenReturn(true)
          val body = contentAsString(
            f.controller.callback.apply(
              FakeRequest(GET, s"/oauth/callback?state=$state&code=example")
                .withCookies(Cookie("mr_oauth", browser))
            )
          )
          body.contains("mark them fixed, not an issue, already fixed or too hard") mustBe write
          body.contains("It cannot edit tasks") mustBe !write
      }
    }

    "allow a loopback editor callback in form-action and name the editor permissions" in {
      val loopback = "http://127.0.0.1:8111/oauth_authorization"
      val editorConfig = Configuration(
        ConfigFactory.parseString(
          s"""
    oauthProvider {
      enabled=true
      callbackUri="https://mr.example/oauth/callback"
      clients=[{
        id="app",name="Editor",redirectUris=["$loopback"],
        scopes=["tasks:read","tasks:write","tasks:edit"]
      }]
    }
  """
        )
      )
      val f = new Fixture(config = Some(editorConfig))
      when(f.store.claimLogin(anyString(), anyString(), any[Instant])).thenReturn(
        Some(interaction.copy(redirectUri = loopback, scope = "tasks:read tasks:write tasks:edit"))
      )
      when(f.store.completeLogin(anyString(), anyString(), anyLong(), anyString(), any[Instant]))
        .thenReturn(true)
      val result = f.controller.callback.apply(
        FakeRequest(GET, s"/oauth/callback?state=$state&code=example")
          .withCookies(Cookie("mr_oauth", browser))
      )
      status(result) mustBe OK
      header("Content-Security-Policy", result).get must include(
        "form-action 'self' http://127.0.0.1:8111;"
      )
      val body = contentAsString(result)
      body must include("request a review")
      body must include("comment on tasks")
      body must include("bundle tasks")
      body must include("It cannot edit OpenStreetMap")
    }

    "persist the requested canonical scope at authorization" in {
      val f      = new Fixture()
      val stored = org.mockito.ArgumentCaptor.forClass(classOf[OAuthInteraction])
      val result = f.controller.authorize.apply(
        FakeRequest(
          GET,
          "/oauth/authorize?response_type=code&client_id=app" +
            "&redirect_uri=org.example.app%3A%2Fcallback&scope=tasks%3Awrite+tasks%3Aread" +
            s"&state=native&code_challenge=${"a" * 43}&code_challenge_method=S256"
        )
      )
      // The upstream redirect builder is not stubbed; only the stored interaction matters here.
      Await.ready(result, 5.seconds)
      verify(f.store).createInteraction(stored.capture())
      stored.getValue.scope mustBe "tasks:read tasks:write"
    }

    "reject invalid consent CSRF and return only code and client state after approval" in {
      val f = new Fixture()
      when(f.store.getInteraction(anyString(), anyString(), any[Instant]))
        .thenReturn(Some(interaction))
      when(
        f.store.approveInteraction(
          anyString(),
          anyString(),
          anyString(),
          anyString(),
          anyString(),
          any[Instant],
          any[Instant]
        )
      ).thenReturn(None)
      def request =
        FakeRequest(POST, "/oauth/consent")
          .withCookies(Cookie("mr_oauth", browser))
          .withFormUrlEncodedBody("interaction" -> state, "csrf" -> csrf, "decision" -> "allow")
      status(call(f.controller.consent, request)) mustBe BAD_REQUEST
      when(
        f.store.approveInteraction(
          anyString(),
          anyString(),
          anyString(),
          anyString(),
          anyString(),
          any[Instant],
          any[Instant]
        )
      ).thenReturn(Some(grant))
      val result = call(f.controller.consent, request)
      status(result) mustBe SEE_OTHER
      val location = redirectLocation(result).get
      location must startWith("org.example.app:/callback?code=")
      location must include("state=native-state")
      location must not include "access_token"
      location must not include "private-global-key"
    }

    "return a credential-free identity projection" in {
      val f = new Fixture()
      when(f.store.authenticate(anyString(), any[Instant])).thenReturn(Some(grant))
      when(f.users.retrieve(42L)).thenReturn(Some(user))
      val result = f.controller.me.apply(
        FakeRequest(GET, "/oauth/me")
          .withHeaders(AUTHORIZATION -> s"Bearer ${OAuthSecrets.generate()}")
      )
      status(result) mustBe OK
      contentAsJson(result) mustBe Json.obj(
        "id"          -> 42,
        "osmId"       -> 99,
        "displayName" -> "Example User",
        "scope"       -> "tasks:read"
      )
    }
  }
}
