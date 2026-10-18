package org.maproulette.auth.oauth

import java.time.Instant

/** Pending browser authorization. No OSM token or raw credential is persisted. */
case class OAuthInteraction(
    idHash: String,
    browserHash: String,
    clientId: String,
    redirectUri: String,
    scope: String,
    clientState: String,
    codeChallenge: String,
    expiresAt: Instant,
    userId: Option[Long] = None,
    csrfHash: Option[String] = None
)

/** Immutable authorization context used by the OAuth library and the resource-server gate. */
case class OAuthGrant(
    familyId: String,
    userId: Long,
    clientId: String,
    scope: String,
    redirectUri: String,
    codeChallenge: String
)

case class TokenHashes(
    accessHash: String,
    refreshHash: String,
    accessExpiresAt: Instant,
    refreshExpiresAt: Instant
)

/** Implementations commit replay revocation before returning None. */
@com.google.inject.ImplementedBy(classOf[OAuthRepository])
trait OAuthStore {
  def createInteraction(interaction: OAuthInteraction): Unit
  def getInteraction(idHash: String, browserHash: String, now: Instant): Option[OAuthInteraction]
  def claimLogin(idHash: String, browserHash: String, now: Instant): Option[OAuthInteraction]
  def completeLogin(
      idHash: String,
      browserHash: String,
      userId: Long,
      csrfHash: String,
      now: Instant
  ): Boolean
  def approveInteraction(
      idHash: String,
      browserHash: String,
      csrfHash: String,
      codeHash: String,
      familyId: String,
      codeExpiresAt: Instant,
      now: Instant
  ): Option[OAuthGrant]
  def declineInteraction(
      idHash: String,
      browserHash: String,
      csrfHash: String,
      now: Instant
  ): Option[OAuthInteraction]
  def findCode(codeHash: String, now: Instant): Option[OAuthGrant]
  def findRefresh(refreshHash: String, now: Instant): Option[OAuthGrant]
  def redeemCode(
      codeHash: String,
      clientId: String,
      redirectUri: String,
      pkceChallenge: String,
      pair: TokenHashes,
      now: Instant
  ): Option[OAuthGrant]
  def rotate(
      refreshHash: String,
      clientId: String,
      pair: TokenHashes,
      now: Instant
  ): Option[OAuthGrant]
  def authenticate(accessHash: String, now: Instant): Option[OAuthGrant]
  def revoke(tokenHash: String, clientId: String, now: Instant): Unit
}
