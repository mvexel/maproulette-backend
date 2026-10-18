package org.maproulette.auth.oauth

import javax.inject.{Inject, Singleton}
import org.maproulette.Config
import org.maproulette.framework.model.User
import play.api.libs.ws.WSClient
import scala.concurrent.{ExecutionContext, Future}

/** Verifies OSM identity without consulting development impersonation, cookies or API keys. */
@Singleton
class OAuthOSMIdentity @Inject() (
    ws: WSClient,
    config: Config,
    provisioner: OAuthUserProvisioner
)(implicit ec: ExecutionContext) {
  def resolve(accessToken: String): Future[User] = {
    if (accessToken.isEmpty)
      return Future.failed(new IllegalArgumentException("Missing OSM credential"))
    ws.url(s"${config.getOSMServer}/api/0.6/user/details")
      .withFollowRedirects(false)
      .withHttpHeaders("Authorization" -> s"Bearer $accessToken")
      .get()
      .map { response =>
        if (response.status != 200)
          throw new IllegalArgumentException("OSM identity verification failed")
        // OSM credentials are never copied into the existing web-session credential column.
        val profile = User.generate(response.body, "", config)
        require(profile.osmProfile.id > 0, "Invalid OSM identity")
        provisioner.resolve(profile)
      }
      .recoverWith {
        case _: Exception =>
          Future.failed(new IllegalArgumentException("OSM identity verification failed"))
      }
  }
}
