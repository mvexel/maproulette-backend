package org.maproulette.auth.oauth

import javax.inject.{Inject, Singleton}
import java.net.URI
import play.api.Configuration

case class OAuthClient(
    id: String,
    name: String,
    redirectUris: Set[String],
    scopes: Set[String] = Set(OAuthScopes.Read),
    enabled: Boolean = true
)

/**
  * OAuth scope sets. A grant always includes `tasks:read`; `tasks:write` (the task lifecycle) is an
  * optional addition, and `tasks:edit` (desktop editors: review requests, completion responses,
  * comments, refreshLock, the changeset link and task bundles, see [[OAuthEditorRoutes]]) is only
  * valid together with `tasks:write`.
  */
object OAuthScopes {
  val Read  = "tasks:read"
  val Write = "tasks:write"
  val Edit  = "tasks:edit"
  // Canonical order for stored and returned scope strings.
  private val supported = Seq(Read, Write, Edit)

  /** Strict RFC 6749 scope parsing: single-space separated, known, unique, with `tasks:read`. */
  def parse(value: String): Option[Set[String]] = {
    val items = value.split(" ", -1).toSeq
    val valid = items.forall(supported.contains) && items.distinct.size == items.size &&
      items.contains(Read) && (!items.contains(Edit) || items.contains(Write))
    if (valid) Some(items.toSet) else None
  }

  def format(scopes: Set[String]): String = supported.filter(scopes.contains).mkString(" ")
}

/** The provider is inert unless explicitly configured and enabled. */
@Singleton
class OAuthSettings @Inject() (configuration: Configuration) {
  val enabled: Boolean =
    configuration.getOptional[Boolean]("oauthProvider.enabled").getOrElse(false)
  val callbackUri: String =
    configuration.getOptional[String]("oauthProvider.callbackUri").getOrElse("")
  val accessSeconds: Long =
    configuration.getOptional[Long]("oauthProvider.accessSeconds").getOrElse(900L)
  val refreshSeconds: Long =
    configuration.getOptional[Long]("oauthProvider.refreshSeconds").getOrElse(2592000L)
  val interactionSeconds: Long = 600L
  val codeSeconds: Long        = 120L

  /** Clients listed in `oauthProvider.clients`; read at runtime through [[OAuthClientRegistry]]. */
  val clients: Map[String, OAuthClient] =
    if (!enabled) Map.empty
    else {
      val entries =
        configuration.getOptional[Seq[Configuration]]("oauthProvider.clients").getOrElse(Seq.empty)
      val parsed = entries.map { entry =>
        val id        = entry.get[String]("id")
        val redirects = entry.get[Seq[String]]("redirectUris").toSet
        require(id.matches("[A-Za-z0-9._-]{1,100}"), "Invalid OAuth client ID")
        require(
          redirects.nonEmpty && redirects.size <= 10 &&
            redirects.forall(OAuthSettings.validRedirect),
          "Invalid OAuth client redirect URI"
        )
        val name = entry.get[String]("name")
        require(name.nonEmpty && name.length <= 200, "Invalid OAuth client name")
        val scopes = OAuthScopes
          .parse(
            entry.getOptional[Seq[String]]("scopes").getOrElse(Seq(OAuthScopes.Read)).mkString(" ")
          )
          .getOrElse(throw new IllegalArgumentException("Invalid OAuth client scopes"))
        OAuthClient(
          id,
          name,
          redirects,
          scopes,
          entry.getOptional[Boolean]("enabled").getOrElse(true)
        )
      }
      require(parsed.map(_.id).distinct.size == parsed.size, "Duplicate OAuth client IDs")
      parsed.map(client => client.id -> client).toMap
    }
  private val allowHttp =
    configuration.getOptional[Boolean]("oauthProvider.allowInsecureLoopback").getOrElse(false)
  private def loopback(uri: URI) = Set("localhost", "127.0.0.1", "[::1]").contains(uri.getHost)

  if (enabled) {
    val uri = new URI(callbackUri)
    require(
      uri.getScheme == "https" || (allowHttp && loopback(uri) && uri.getScheme == "http"),
      "Invalid OAuth callback URI"
    )
    require(
      uri.getHost != null && uri.getUserInfo == null && uri.getFragment == null && uri.getQuery == null,
      "Invalid OAuth callback URI"
    )
    require(
      accessSeconds > 0 && accessSeconds <= 3600 && refreshSeconds >= accessSeconds && refreshSeconds <= 7776000,
      "Invalid OAuth credential lifetime"
    )
  }
  def secureCookie: Boolean = callbackUri.startsWith("https://")
}

object OAuthSettings {

  /**
    * A registered app callback: https with a host, a reverse-domain custom scheme, or an http
    * loopback IP literal with an explicit port and path (RFC 8252 §7.3; desktop editors such as
    * JOSM, whose Remote Control listens on 127.0.0.1:8111). `localhost` is refused (RFC 8252 §8.3).
    * Matching stays exact, so the port is part of the registration. No fragment, query or user
    * info, because the code is appended as the query.
    */
  def validRedirect(value: String): Boolean =
    scala.util
      .Try {
        val uri    = new URI(value)
        val scheme = Option(uri.getScheme).getOrElse("")
        val web    = scheme == "https" && uri.getHost != null
        val native = scheme.contains(".") && scheme.matches("[a-z][a-z0-9+.-]*")
        val loopback = scheme == "http" && Set("127.0.0.1", "[::1]").contains(uri.getHost) &&
          uri.getPort > 0 && Option(uri.getRawPath).exists(_.startsWith("/"))
        (web || native || loopback) && uri.getFragment == null && uri.getUserInfo == null &&
        uri.getQuery == null
      }
      .getOrElse(false)
}
