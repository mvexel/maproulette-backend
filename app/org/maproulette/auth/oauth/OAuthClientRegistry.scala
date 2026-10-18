package org.maproulette.auth.oauth

import javax.inject.{Inject, Singleton}

/**
  * The approved OAuth clients. Only enabled clients can authorize, exchange codes, refresh or
  * authenticate; [[known]] also includes disabled ones (revocation stays possible).
  */
@com.google.inject.ImplementedBy(classOf[StaticOAuthClientRegistry])
trait OAuthClientRegistry {

  /** Every client, enabled or not, ordered by id. */
  def all: Seq[OAuthClient]
  def known(id: String): Option[OAuthClient] = all.find(_.id == id)
  def get(id: String): Option[OAuthClient]   = known(id).filter(_.enabled)

  /** The grant's scopes while its client is enabled and still allows all of them. */
  def allowedScopes(clientId: String, scope: String): Option[Set[String]] =
    OAuthClientRegistry.allowedScopes(get(clientId), scope)
}

object OAuthClientRegistry {
  def allowedScopes(client: Option[OAuthClient], scope: String): Option[Set[String]] =
    for {
      value  <- client if value.enabled
      scopes <- OAuthScopes.parse(scope) if scopes.subsetOf(value.scopes)
    } yield scopes
}

/** The clients configured in `oauthProvider.clients`. */
@Singleton
class StaticOAuthClientRegistry @Inject() (settings: OAuthSettings) extends OAuthClientRegistry {
  val all: Seq[OAuthClient] = settings.clients.values.toSeq.sortBy(_.id)
}
