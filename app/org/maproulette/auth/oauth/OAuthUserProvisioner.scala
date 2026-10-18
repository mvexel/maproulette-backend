package org.maproulette.auth.oauth

import anorm._
import javax.inject.{Inject, Singleton}
import java.util.UUID
import org.maproulette.framework.model.User
import org.maproulette.framework.service.UserService
import org.maproulette.utils.Crypto
import play.api.db.Database

/** OAuth sign-in never updates existing credentials, including during a concurrent web login. */
@Singleton
class OAuthUserProvisioner @Inject() (db: Database, users: UserService, crypto: Crypto) {
  def resolve(profile: User): User = {
    users.retrieveByOSMId(profile.osmProfile.id) match {
      case Some(existing) => existing
      case None =>
        val inserted = db.withConnection { implicit connection =>
          SQL("""
            insert into users (api_key, osm_id, osm_created, name, description,
              avatar_url, oauth_token, oauth_secret, home_location)
            values ({apiKey}, {osmId}, {created}, {name}, {description}, {avatar}, '', '',
              ST_GeomFromEWKT({home}))
            on conflict (osm_id) do nothing
          """)
            .on(
              Symbol("apiKey")      -> crypto.encrypt(UUID.randomUUID().toString),
              Symbol("osmId")       -> profile.osmProfile.id,
              Symbol("created")     -> new java.sql.Timestamp(profile.osmProfile.created.getMillis),
              Symbol("name")        -> profile.osmProfile.displayName,
              Symbol("description") -> profile.osmProfile.description,
              Symbol("avatar")      -> profile.osmProfile.avatarURL,
              // Preserve the existing repository's home-location coordinate convention.
              Symbol("home") -> s"SRID=4326;POINT(${profile.osmProfile.homeLocation.latitude} ${profile.osmProfile.homeLocation.longitude})"
            )
            .executeUpdate() == 1
        }
        val user = users
          .retrieveByOSMId(profile.osmProfile.id)
          .getOrElse(throw new IllegalStateException("Account initialization failed"))
        if (inserted) users.initializeHomeProject(user) else user
    }
  }
}
