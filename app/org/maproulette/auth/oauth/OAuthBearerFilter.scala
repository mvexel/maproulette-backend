package org.maproulette.auth.oauth

import akka.stream.Materializer
import javax.inject.Inject
import org.maproulette.framework.model.User
import org.maproulette.framework.service.UserService
import org.maproulette.session.SessionManager
import play.api.libs.json.Json
import play.api.libs.typedmap.TypedKey
import play.api.mvc.{Filter, RequestHeader, Result, Results}
import scala.concurrent.{ExecutionContext, Future}

object OAuthBearerIdentity {
  val UserKey: TypedKey[User] = TypedKey[User]("oauth-bearer-user")
  // The grant's scopes, family and client, for controllers that need more than the user.
  val ScopesKey: TypedKey[Set[String]] = TypedKey[Set[String]]("oauth-bearer-scopes")
  val FamilyKey: TypedKey[String]      = TypedKey[String]("oauth-bearer-family")
  val ClientKey: TypedKey[String]      = TypedKey[String]("oauth-bearer-client")
}

/** An explicit route allowlist: several legacy GET routes mutate data or disclose API keys. */
object OAuthReadRoutes {
  private val number = "[+-]?[0-9]+(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?"
  private val box    = s"$number/$number/$number/$number"
  private val reads = Seq(
    "/api/v2/challenges/extendedFind",
    "/api/v2/challenge/[0-9]+",
    "/api/v2/challenge/[0-9]+/tags",
    "/api/v2/challenge/[0-9]+/tasks",
    "/api/v2/task/[0-9]+",
    s"/api/v2/tasks/box/$box",
    "/oauth/me"
  ).map(_.r)

  def permits(method: String, path: String): Boolean =
    (method == "GET" && reads.exists(_.pattern.matcher(path).matches())) ||
      (method == "PUT" && path.matches(s"/api/v2/markers/box/$box"))
}

/**
  * Task lifecycle writes for grants with `tasks:write`. Only the bare route is allowed: no query
  * string (which would carry requestReview or tags) and no body (completion responses). Status
  * codes are limited to Fixed, False positive, Already fixed and Too hard. Clients with only
  * `tasks:write` lock late (start immediately before the status write), so refreshLock is not
  * allowed here; desktop editors get it, and the extras above, through [[OAuthEditorRoutes]] with `tasks:edit`.
  */
object OAuthWriteRoutes {
  private val task = "/api/v2/task/[0-9]+"

  def permits(method: String, path: String): Boolean = method match {
    case "GET"  => path.matches(s"$task/(start|release)")
    case "POST" => path.matches(s"$task/skip")
    case "PUT"  => path.matches(s"$task/[1256]")
    case _      => false
  }
}

/**
  * Desktop editor writes for grants with `tasks:edit` (which implies `tasks:write`): the status
  * write with its review request, tags and completion responses, task comments, refreshLock (an
  * editing session outlasts the lock) and the changeset link, plus the task bundle routes: create,
  * read, update, unbundle, delete, lock and unlock, bundle status and bundle comments (not bundle
  * review). Each route takes only the listed query keys, each at most once except `taskIds` (at
  * most [[MaxBundleTasks]] values), and only the status writes, the comments and bundle create take
  * a JSON body of at most [[MaxBodyBytes]]. A bare status write stays a [[OAuthWriteRoutes]]
  * lifecycle write.
  */
object OAuthEditorRoutes {
  private val task   = "/api/v2/task/[0-9]+"
  val MaxBodyBytes   = 16384
  val MaxValueLength = 1024

  private def status(method: String, path: String) =
    method == "PUT" && path.matches(s"$task/[1256]")
  private def comment(method: String, path: String) =
    method == "POST" && path.matches(s"$task/comment")

  private def changeset(method: String, path: String) =
    method == "PUT" && path.matches(s"$task/changeset")
  private val digits: String => Boolean = _.matches("[0-9]{1,18}")

  private val bundle = "/api/v2/taskBundle/[0-9]+"
  // Same cap as the web UI's bundle limit.
  val MaxBundleTasks = 50

  private def bundleCreate(method: String, path: String) =
    method == "POST" && path == "/api/v2/taskBundle"
  private def bundleStatus(method: String, path: String) =
    method == "PUT" && path.matches(s"$bundle/[1256]")
  private def bundleComment(method: String, path: String) =
    method == "POST" && path.matches(s"$bundle/comment")
  // Routes whose only query is the required `taskIds` list.
  private def bundleMembers(method: String, path: String) =
    method == "POST" && path.matches(s"$bundle/(update|unbundle)") ||
      method == "POST" && path == "/api/v2/task/bundle/unlock"
  private def lockBundle(method: String, path: String) =
    method == "PUT" && path.matches(s"$task/lockBundle")
  private def bundleBare(method: String, path: String) =
    (method == "POST" || method == "DELETE") && path.matches(bundle)

  private def bundleRoute(method: String, path: String) =
    bundleCreate(method, path) || bundleStatus(method, path) || bundleComment(method, path) ||
      bundleMembers(method, path) || lockBundle(method, path) || bundleBare(method, path)

  def permits(method: String, path: String): Boolean =
    status(method, path) || comment(method, path) || changeset(method, path) ||
      method == "GET" && path.matches(s"$task/refreshLock") || bundleRoute(method, path)

  /** True when the request needs `tasks:edit`: an editor-only route, or a status write with extras. */
  def requires(request: RequestHeader): Boolean =
    permits(request.method, request.path) &&
      (!OAuthWriteRoutes.permits(request.method, request.path) ||
        request.rawQueryString.nonEmpty || request.hasBody)

  private def query(request: RequestHeader): Boolean = {
    val (method, path) = (request.method, request.path)
    // Only "true": "false" would skip a review the user's settings make mandatory.
    val review: (String, String => Boolean) = "requestReview" -> Set("true")
    val allowed: Map[String, String => Boolean] =
      if (status(method, path)) Map(review, "tags" -> (_ => true))
      else if (bundleStatus(method, path))
        Map("primaryId" -> digits, review, "tags" -> (_ => true))
      else if (comment(method, path) || bundleComment(method, path)) Map("actionId" -> digits)
      else if (changeset(method, path)) Map("changesetId" -> digits)
      else if (bundleMembers(method, path) || lockBundle(method, path)) Map("taskIds" -> digits)
      else Map.empty
    val required =
      if (bundleStatus(method, path)) Set("primaryId")
      else if (bundleMembers(method, path)) Set("taskIds")
      else Set.empty[String]
    def values(key: String, given: Seq[String]) =
      given.nonEmpty && given.size <= (if (key == "taskIds") MaxBundleTasks else 1)
    required.subsetOf(request.queryString.keySet) && request.queryString.forall {
      case (key, given) =>
        values(key, given) && allowed.get(key).exists { valid =>
          given.forall(value => value.length <= MaxValueLength && valid(value))
        }
    }
  }

  private def takesBody(method: String, path: String) =
    status(method, path) || comment(method, path) || bundleStatus(method, path) ||
      bundleComment(method, path) || bundleCreate(method, path)

  // Comments and bundle create need their JSON; status writes may omit completion responses.
  private def needsBody(method: String, path: String) =
    comment(method, path) || bundleComment(method, path) || bundleCreate(method, path)

  private def body(request: RequestHeader): Boolean =
    if (!takesBody(request.method, request.path)) !request.hasBody
    else if (!request.hasBody) !needsBody(request.method, request.path)
    else {
      val contentType = request.headers
        .get("Content-Type")
        .map(_.toLowerCase(java.util.Locale.ROOT).replace(" ", ""))
      val length = request.headers.getAll("Content-Length") match {
        case Seq(value) if value.matches("[0-9]{1,5}") => Some(value.toInt)
        case _                                         => None
      }
      request.headers.get("Transfer-Encoding").isEmpty &&
      contentType.exists(Set("application/json", "application/json;charset=utf-8").contains) &&
      length.exists(value => value > 0 && value <= MaxBodyBytes)
    }

  def acceptable(request: RequestHeader): Boolean = query(request) && body(request)
}

/** Requests without a bearer token pass through unchanged; bearer credentials never fall back. */
class OAuthBearerFilter @Inject() (
    settings: OAuthSettings,
    oauth: OAuthService,
    users: UserService
)(implicit val mat: Materializer, ec: ExecutionContext)
    extends Filter {

  private def denied(status: Int, code: String): Future[Result] = Future.successful(
    Results
      .Status(status)(Json.obj("error" -> code))
      .withHeaders("Cache-Control" -> "no-store", "WWW-Authenticate" -> "Bearer")
  )

  def apply(next: RequestHeader => Future[Result])(request: RequestHeader): Future[Result] = {
    val authorizations = request.headers.getAll("Authorization")
    val bearer         = authorizations.exists(_.toLowerCase(java.util.Locale.ROOT).startsWith("bearer"))
    if (!settings.enabled || !bearer) return next(request)
    // A bearer request that also carries an API key or a web session is ambiguous and refused.
    if (authorizations.size != 1 || request.headers.get("apiKey").isDefined ||
        request.session.get(SessionManager.KEY_TOKEN_HASH).isDefined ||
        request.session.get(SessionManager.KEY_USER_ID).isDefined)
      return denied(401, "invalid_token")
    val parts = authorizations.head.split(" ", -1)
    if (parts.length != 2 || !parts(0).equalsIgnoreCase("Bearer") ||
        !parts(1).matches("[A-Za-z0-9_-]{32,256}")) return denied(401, "invalid_token")
    val editor = OAuthEditorRoutes.requires(request)
    val write  = OAuthWriteRoutes.permits(request.method, request.path) || editor
    val read   = OAuthReadRoutes.permits(request.method, request.path)
    if (!write && !read) return denied(403, "insufficient_scope")
    val badShape =
      if (editor) !OAuthEditorRoutes.acceptable(request)
      else write && (request.rawQueryString.nonEmpty || request.hasBody)
    if (badShape) return denied(400, "invalid_request")
    oauth.authenticate(parts(1)).flatMap { grant =>
      // OAuthService.authenticate has already checked the scopes against the client.
      grant.flatMap(value => OAuthScopes.parse(value.scope).map(value -> _)) match {
        case Some((value, scopes)) =>
          if (write && !scopes.contains(OAuthScopes.Write) ||
              editor && !scopes.contains(OAuthScopes.Edit)) denied(403, "insufficient_scope")
          else
            users.retrieve(value.userId).filter(_.id > 0) match {
              case Some(user) =>
                next(
                  request
                    .addAttr(OAuthBearerIdentity.UserKey, user)
                    .addAttr(OAuthBearerIdentity.ScopesKey, scopes)
                    .addAttr(OAuthBearerIdentity.FamilyKey, value.familyId)
                    .addAttr(OAuthBearerIdentity.ClientKey, value.clientId)
                )
              case None => denied(401, "invalid_token")
            }
        case None => denied(401, "invalid_token")
      }
    }
  }
}
