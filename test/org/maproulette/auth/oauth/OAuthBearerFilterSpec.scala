package org.maproulette.auth.oauth

import akka.actor.ActorSystem
import akka.stream.{Materializer, SystemMaterializer}
import org.joda.time.DateTime
import org.maproulette.framework.model.{Location, OSMProfile, User}
import org.maproulette.framework.service.UserService
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.{never, verify, when}
import org.scalatest.BeforeAndAfterAll
import org.scalatestplus.mockito.MockitoSugar
import org.scalatestplus.play.PlaySpec
import play.api.Configuration
import play.api.mvc.{RequestHeader, Results}
import play.api.test.FakeRequest
import play.api.test.Helpers._
import scala.concurrent.{ExecutionContext, Future}

class OAuthBearerFilterSpec extends PlaySpec with MockitoSugar with BeforeAndAfterAll {
  private implicit val system: ActorSystem        = ActorSystem("oauth-bearer-tests")
  private implicit val materializer: Materializer = SystemMaterializer(system).materializer
  private implicit val ec: ExecutionContext       = system.dispatcher
  private val token                               = "A" * 43
  private val user = User(
    123,
    DateTime.now(),
    DateTime.now(),
    OSMProfile(456, "Mapper", "", "", Location(1, 2), DateTime.now(), "legacy-token"),
    List.empty
  )
  private val grant = OAuthGrant(
    "family",
    123,
    "test-client",
    "tasks:read",
    "org.example.app:/callback",
    "challenge"
  )
  override def afterAll(): Unit = { await(system.terminate()); super.afterAll() }

  private def settings(enabled: Boolean) =
    new OAuthSettings(
      Configuration.from(
        Map(
          "oauthProvider.enabled"     -> enabled,
          "oauthProvider.callbackUri" -> "https://example.org/oauth/callback"
        )
      )
    )
  private def next(request: RequestHeader) =
    Future.successful(
      Results
        .Ok(request.attrs.get(OAuthBearerIdentity.UserKey).map(_.id.toString).getOrElse("legacy"))
    )

  private val writeGrant = grant.copy(scope = "tasks:read tasks:write")
  private val allowedWrites = Seq(
    GET  -> "/api/v2/task/123/start",
    GET  -> "/api/v2/task/123/release",
    POST -> "/api/v2/task/123/skip",
    PUT  -> "/api/v2/task/123/1",
    PUT  -> "/api/v2/task/123/2",
    PUT  -> "/api/v2/task/123/5",
    PUT  -> "/api/v2/task/123/6"
  )
  private def bearer(method: String, path: String) =
    FakeRequest(method, path).withHeaders("Authorization" -> s"Bearer $token")
  private def json(request: FakeRequest[_], body: String, extra: (String, String)*) =
    request
      .withHeaders(
        Seq("Content-Type" -> "application/json", "Content-Length" -> body.length.toString) ++ extra: _*
      )
      .withBody(body)
  private val editGrant = grant.copy(scope = "tasks:read tasks:write tasks:edit")
  private def editorRequests = Seq(
    bearer(PUT, "/api/v2/task/123/1?requestReview=true"),
    bearer(PUT, "/api/v2/task/123/2?requestReview=true&tags=a,b"),
    json(bearer(PUT, "/api/v2/task/123/5"), """{"answer":"yes"}"""),
    json(bearer(PUT, "/api/v2/task/123/6?tags=x"), "x" * 16384),
    json(bearer(POST, "/api/v2/task/123/comment"), """{"comment":"done"}"""),
    json(bearer(POST, "/api/v2/task/123/comment?actionId=7"), """{"comment":"done"}"""),
    bearer(GET, "/api/v2/task/123/refreshLock"),
    bearer(PUT, "/api/v2/task/123/changeset"),
    bearer(PUT, "/api/v2/task/123/changeset?changesetId=987654"),
    json(bearer(POST, "/api/v2/taskBundle"), """{"name":"b","taskIds":[123,124]}"""),
    bearer(POST, "/api/v2/taskBundle/9"),
    bearer(DELETE, "/api/v2/taskBundle/9"),
    bearer(POST, "/api/v2/taskBundle/9/update?taskIds=123&taskIds=124"),
    bearer(POST, "/api/v2/taskBundle/9/unbundle?taskIds=124"),
    bearer(PUT, "/api/v2/task/123/lockBundle"),
    bearer(PUT, "/api/v2/task/123/lockBundle?taskIds=123&taskIds=124"),
    bearer(POST, "/api/v2/task/bundle/unlock?taskIds=123&taskIds=124"),
    bearer(PUT, "/api/v2/taskBundle/9/1?primaryId=123"),
    bearer(PUT, "/api/v2/taskBundle/9/2?primaryId=123&requestReview=true&tags=a"),
    json(bearer(PUT, "/api/v2/taskBundle/9/5?primaryId=123"), """{"answer":"yes"}"""),
    json(bearer(POST, "/api/v2/taskBundle/9/comment?actionId=7"), """{"comment":"done"}""")
  )
  private def writeFilter(scopedGrant: OAuthGrant) = {
    val oauth = mock[OAuthService]
    val users = mock[UserService]
    when(oauth.authenticate(token)).thenReturn(Future.successful(Some(scopedGrant)))
    when(users.retrieve(123)).thenReturn(Some(user))
    (new OAuthBearerFilter(settings(true), oauth, users), oauth)
  }

  "OAuth scope parsing" should {
    "accept read and read+write sets in either order and format them canonically" in {
      OAuthScopes.parse("tasks:read") mustBe Some(Set("tasks:read"))
      OAuthScopes.parse("tasks:write tasks:read") mustBe Some(Set("tasks:read", "tasks:write"))
      OAuthScopes.format(Set("tasks:write", "tasks:read")) mustBe "tasks:read tasks:write"
    }
    "reject empty, unknown, duplicate, write-only and irregularly spaced scopes" in {
      Seq(
        "",
        "tasks:write",
        "tasks:read tasks:read",
        "tasks:read tasks:delete",
        "tasks:read  tasks:write",
        " tasks:read",
        "tasks:read\ttasks:write",
        "TASKS:READ"
      ).foreach(value => OAuthScopes.parse(value) mustBe None)
    }
  }

  "OAuth task write gate" should {
    "allow each audited lifecycle route for a tasks:write grant" in {
      val (filter, _) = writeFilter(writeGrant)
      allowedWrites.foreach {
        case (method, path) =>
          contentAsString(filter.apply(next)(bearer(method, path))) mustBe "123"
      }
    }

    "deny every lifecycle route to a legacy tasks:read grant with insufficient_scope" in {
      val (filter, _) = writeFilter(grant)
      allowedWrites.foreach {
        case (method, path) =>
          val result = filter.apply(next)(bearer(method, path))
          status(result) mustBe FORBIDDEN
          contentAsJson(result) mustBe play.api.libs.json.Json.obj("error" -> "insufficient_scope")
      }
      contentAsString(filter.apply(next)(bearer(GET, "/api/v2/task/123"))) mustBe "123"
    }

    "deny unaudited writes and status codes even with tasks:write, before authentication" in {
      val (filter, oauth) = writeFilter(writeGrant)
      Seq(
        PUT    -> "/api/v2/task/123/0",
        PUT    -> "/api/v2/task/123/3",
        PUT    -> "/api/v2/task/123/4",
        PUT    -> "/api/v2/task/123/7",
        PUT    -> "/api/v2/task/123/8",
        PUT    -> "/api/v2/task/123/9",
        PUT    -> "/api/v2/task/123/01",
        PUT    -> "/api/v2/task/123/12",
        PUT    -> "/api/v2/task/123/-1",
        PUT    -> "/api/v2/task/123/1/",
        PUT    -> "/api/v2/task/123/%31",
        POST   -> "/api/v2/task/123/1",
        GET    -> "/api/v2/task/123/1",
        GET    -> "/api/v2/task/123/skip",
        PUT    -> "/api/v2/task/123/skip",
        POST   -> "/api/v2/task/123/start",
        PUT    -> "/api/v2/task/123/start",
        GET    -> "/api/v2/task/123/start/",
        GET    -> "/api/v2/task/abc/start",
        PUT    -> "/api/v2/task/123/unlock/request",
        GET    -> "/api/v2/task/123/tags/update",
        GET    -> "/api/v2/task/123/review/start",
        POST   -> "/api/v2/task/123/lockBundle",
        PUT    -> "/api/v2/task/123",
        DELETE -> "/api/v2/task/123",
        PUT    -> "/api/v2/task/123/review/1",
        PUT    -> "/api/v2/tasks/changeStatus",
        PUT    -> "/api/v2/taskBundle",
        PUT    -> "/api/v2/taskBundle/1/review/1",
        GET    -> "/api/v2/challenge/1/start",
        POST   -> "/api/v2/task/123/changeset"
      ).foreach {
        case (method, path) =>
          status(filter.apply(next)(bearer(method, path))) mustBe FORBIDDEN
      }
      verify(oauth, never()).authenticate(anyString())
    }

    "reject a query string or body on write routes, including review and tag overrides" in {
      val (filter, oauth) = writeFilter(writeGrant)
      Seq(
        bearer(PUT, "/api/v2/task/123/1?requestReview=maybe"),
        bearer(PUT, "/api/v2/task/123/1?comment=hi"),
        bearer(GET, "/api/v2/task/123/start?x=1"),
        bearer(POST, "/api/v2/task/123/skip?x=1"),
        bearer(PUT, "/api/v2/task/123/1").withHeaders("Content-Length"     -> "8"),
        bearer(PUT, "/api/v2/task/123/2").withHeaders("Transfer-Encoding"  -> "chunked"),
        bearer(POST, "/api/v2/task/123/skip").withHeaders("Content-Length" -> "2")
      ).foreach { request =>
        val result = filter.apply(next)(request)
        status(result) mustBe BAD_REQUEST
        contentAsJson(result) mustBe play.api.libs.json.Json.obj("error" -> "invalid_request")
      }
      contentAsString(
        filter.apply(next)(bearer(PUT, "/api/v2/task/123/1").withHeaders("Content-Length" -> "0"))
      ) mustBe "123"
      verify(oauth).authenticate(token)
    }

    "deny editor requests to a tasks:write grant with insufficient_scope" in {
      val (filter, _) = writeFilter(writeGrant)
      editorRequests.foreach { request =>
        val result = filter.apply(next)(request)
        status(result) mustBe FORBIDDEN
        contentAsJson(result) mustBe play.api.libs.json.Json.obj("error" -> "insufficient_scope")
      }
    }

    "keep query strings on read routes, reject invalid tokens and leave legacy writes unchanged" in {
      val (filter, _) = writeFilter(writeGrant)
      contentAsString(
        filter.apply(next)(bearer(GET, "/api/v2/challenge/1/tasks?limit=5"))
      ) mustBe "123"
      val oauth = mock[OAuthService]
      when(oauth.authenticate(token)).thenReturn(Future.successful(None))
      val invalid = new OAuthBearerFilter(settings(true), oauth, mock[UserService])
      status(invalid.apply(next)(bearer(PUT, "/api/v2/task/123/1"))) mustBe UNAUTHORIZED
      val legacy = mock[OAuthService]
      val open   = new OAuthBearerFilter(settings(true), legacy, mock[UserService])
      Seq(
        FakeRequest(PUT, "/api/v2/task/123/4?requestReview=false")
          .withHeaders("apiKey"                                         -> "legacy-key", "Content-Length" -> "2"),
        FakeRequest(PUT, "/api/v2/task/123/9").withSession("token"      -> "legacy-cookie"),
        FakeRequest(GET, "/api/v2/task/123/start").withHeaders("apiKey" -> "legacy-key")
      ).foreach(request => contentAsString(open.apply(next)(request)) mustBe "legacy")
      verify(legacy, never()).authenticate(anyString())
    }
  }

  "OAuth editor routes" should {
    "allow each editor request and the lifecycle routes for a tasks:edit grant" in {
      val (filter, _) = writeFilter(editGrant)
      (editorRequests ++ allowedWrites.map { case (method, path) => bearer(method, path) })
        .foreach(request => contentAsString(filter.apply(next)(request)) mustBe "123")
    }

    "reject editor requests outside the allowed shapes before authentication" in {
      val (filter, oauth) = writeFilter(editGrant)
      Seq(
        bearer(PUT, "/api/v2/task/123/1?requestReview=yes"),
        bearer(PUT, "/api/v2/task/123/1?requestReview=false"),
        bearer(PUT, "/api/v2/task/123/1?requestReview"),
        bearer(PUT, "/api/v2/task/123/1?requestReview=true&requestReview=false"),
        bearer(PUT, "/api/v2/task/123/1?tags=" + "a" * 1025),
        bearer(PUT, "/api/v2/task/123/1?comment=dropped"),
        bearer(PUT, "/api/v2/task/123/1").withHeaders("Content-Length" -> "2").withBody("{}"),
        json(bearer(PUT, "/api/v2/task/123/1"), "x" * 16385),
        json(bearer(PUT, "/api/v2/task/123/1"), "{}", "Transfer-Encoding" -> "chunked"),
        bearer(POST, "/api/v2/task/123/comment"),
        bearer(POST, "/api/v2/task/123/comment?actionId=abc"),
        json(bearer(POST, "/api/v2/task/123/comment?actionId=1&tags=x"), "{}"),
        bearer(GET, "/api/v2/task/123/refreshLock?x=1"),
        bearer(GET, "/api/v2/task/123/refreshLock").withHeaders("Content-Length" -> "2"),
        bearer(PUT, "/api/v2/task/123/changeset?changesetId=x"),
        bearer(PUT, "/api/v2/task/123/changeset?id=1"),
        json(bearer(PUT, "/api/v2/task/123/changeset"), "{}"),
        bearer(POST, "/api/v2/taskBundle"),
        json(bearer(POST, "/api/v2/taskBundle?name=b"), "{}"),
        bearer(POST, "/api/v2/taskBundle/9?lockTasks=true"),
        json(bearer(DELETE, "/api/v2/taskBundle/9"), "{}"),
        bearer(POST, "/api/v2/taskBundle/9/update"),
        bearer(POST, "/api/v2/taskBundle/9/update?taskIds=1,2"),
        bearer(POST, "/api/v2/taskBundle/9/unbundle?" + Seq.fill(51)("taskIds=1").mkString("&")),
        bearer(PUT, "/api/v2/task/123/lockBundle?taskIds=x"),
        json(bearer(POST, "/api/v2/task/bundle/unlock?taskIds=1"), "[1]"),
        bearer(PUT, "/api/v2/taskBundle/9/1"),
        bearer(PUT, "/api/v2/taskBundle/9/1?primaryId=123&requestReview=false"),
        bearer(PUT, "/api/v2/taskBundle/9/1?primaryId=123&primaryId=124"),
        bearer(POST, "/api/v2/taskBundle/9/comment?actionId=7")
      ).foreach { request =>
        val result = filter.apply(next)(request)
        status(result) mustBe BAD_REQUEST
        contentAsJson(result) mustBe play.api.libs.json.Json.obj("error" -> "invalid_request")
      }
      Seq(
        PUT    -> "/api/v2/task/123/3?requestReview=true",
        POST   -> "/api/v2/task/123/changeset",
        PUT    -> "/api/v2/task/123/comment",
        GET    -> "/api/v2/task/123/comments/x",
        PUT    -> "/api/v2/taskBundle/1/review/1",
        PUT    -> "/api/v2/taskBundle/1/metareview/1",
        PUT    -> "/api/v2/taskBundle/1/3?primaryId=1",
        GET    -> "/api/v2/taskBundle/1",
        DELETE -> "/api/v2/task/123/comment/1"
      ).foreach {
        case (method, path) => status(filter.apply(next)(bearer(method, path))) mustBe FORBIDDEN
      }
      verify(oauth, never()).authenticate(anyString())
    }

  }

  "OAuth bearer boundary" should {
    "leave disabled and non-bearer legacy requests unchanged without consulting the provider" in {
      val oauth    = mock[OAuthService]
      val users    = mock[UserService]
      val disabled = new OAuthBearerFilter(settings(false), oauth, users)
      contentAsString(
        disabled.apply(next)(
          FakeRequest(GET, "/auth/generateAPIKey")
            .withHeaders("Authorization" -> s"Bearer $token", "apiKey" -> "legacy-key")
        )
      ) mustBe "legacy"
      val enabled = new OAuthBearerFilter(settings(true), oauth, users)
      contentAsString(
        enabled.apply(next)(
          FakeRequest(GET, "/api/v2/user/whoami")
            .withHeaders("apiKey" -> "legacy-key")
            .withSession("token" -> "legacy-cookie")
        )
      ) mustBe "legacy"
      verify(oauth, never()).authenticate(anyString())
    }

    "accept a valid scoped token only on explicitly audited reads" in {
      val oauth = mock[OAuthService]
      val users = mock[UserService]
      when(oauth.authenticate(token)).thenReturn(Future.successful(Some(grant)))
      when(users.retrieve(123)).thenReturn(Some(user))
      val filter = new OAuthBearerFilter(settings(true), oauth, users)
      contentAsString(
        filter.apply(next)(
          FakeRequest(GET, "/api/v2/task/123")
            .withHeaders("Authorization" -> s"bearer $token")
        )
      ) mustBe "123"
      contentAsString(
        filter.apply(next)(
          FakeRequest(PUT, "/api/v2/markers/box/-112/40/-111/41")
            .withHeaders("Authorization" -> s"Bearer $token")
        )
      ) mustBe "123"
    }

    "reject mutating GETs, credential-returning identity, other methods and ambiguous paths" in {
      val oauth  = mock[OAuthService]
      val filter = new OAuthBearerFilter(settings(true), oauth, mock[UserService])
      Seq(
        GET  -> "/auth/generateAPIKey",
        GET  -> "/api/v2/user/whoami",
        GET  -> "/api/v2/user/123",
        POST -> "/api/v2/task/123",
        GET  -> "/api/v2/task/123/",
        GET  -> "/api/v2/task/123%2fstart"
      ).foreach {
        case (method, path) =>
          status(
            filter.apply(next)(
              FakeRequest(method, path)
                .withHeaders("Authorization" -> s"Bearer $token")
            )
          ) mustBe FORBIDDEN
      }
      verify(oauth, never()).authenticate(anyString())
    }

    "reject malformed, duplicate and mixed credentials without falling back" in {
      val oauth  = mock[OAuthService]
      val filter = new OAuthBearerFilter(settings(true), oauth, mock[UserService])
      Seq("Bearer", "Bearer\t" + token, "Bearer  " + token, "BearerX " + token).foreach { value =>
        status(
          filter.apply(next)(
            FakeRequest(GET, "/api/v2/task/123")
              .withHeaders("Authorization" -> value, "apiKey" -> "legacy-key")
          )
        ) mustBe UNAUTHORIZED
      }
      status(
        filter.apply(next)(
          FakeRequest(GET, "/api/v2/task/123")
            .withHeaders("Authorization" -> s"Bearer $token", "Authorization" -> s"Bearer $token")
        )
      ) mustBe UNAUTHORIZED
      status(
        filter.apply(next)(
          FakeRequest(GET, "/api/v2/task/123")
            .withHeaders("Authorization" -> s"Bearer $token")
            .withSession("userId" -> "7", "tokenHash" -> "web-session")
        )
      ) mustBe UNAUTHORIZED
      verify(oauth, never()).authenticate(anyString())
    }

    "reject expired/revoked tokens, wrong scope, and deleted accounts" in {
      val oauth  = mock[OAuthService]
      val users  = mock[UserService]
      val filter = new OAuthBearerFilter(settings(true), oauth, users)
      val request =
        FakeRequest(GET, "/api/v2/task/123").withHeaders("Authorization" -> s"Bearer $token")
      when(oauth.authenticate(token)).thenReturn(Future.successful(None))
      status(filter.apply(next)(request)) mustBe UNAUTHORIZED
      when(oauth.authenticate(token))
        .thenReturn(Future.successful(Some(grant.copy(scope = "unknown"))))
      status(filter.apply(next)(request)) mustBe UNAUTHORIZED
      when(oauth.authenticate(token)).thenReturn(Future.successful(Some(grant)))
      when(users.retrieve(123)).thenReturn(None)
      status(filter.apply(next)(request)) mustBe UNAUTHORIZED
    }
  }

}
