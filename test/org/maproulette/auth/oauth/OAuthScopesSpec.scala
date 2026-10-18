package org.maproulette.auth.oauth

import org.scalatestplus.play.PlaySpec
import play.api.Configuration

class OAuthScopesSpec extends PlaySpec {
  "OAuthScopes.parse" should {
    "require tasks:read and accept only known, unique scopes" in {
      OAuthScopes.parse("tasks:read") mustBe Some(Set("tasks:read"))
      OAuthScopes.parse("tasks:read tasks:write") mustBe Some(Set("tasks:read", "tasks:write"))
      OAuthScopes.parse("tasks:write") mustBe None
      OAuthScopes.parse("tasks:read tasks:read") mustBe None
      OAuthScopes.parse("tasks:read  tasks:write") mustBe None
      OAuthScopes.parse("tasks:read other") mustBe None
      OAuthScopes.parse("") mustBe None
    }
  }

  "OAuthScopes tasks:edit" should {
    "require tasks:write and format in canonical order" in {
      OAuthScopes.parse("tasks:edit tasks:write tasks:read") mustBe
        Some(Set("tasks:read", "tasks:write", "tasks:edit"))
      OAuthScopes.format(Set("tasks:edit", "tasks:read", "tasks:write")) mustBe
        "tasks:read tasks:write tasks:edit"
      OAuthScopes.parse("tasks:read tasks:edit") mustBe None
      OAuthScopes.parse("tasks:edit") mustBe None
    }
  }

  "OAuthSettings.validRedirect" should {
    "accept an http loopback IP literal with a port and path" in {
      Seq(
        "http://127.0.0.1:8111/oauth_authorization",
        "http://[::1]:8111/oauth_authorization",
        "https://app.example/callback",
        "org.example.app:/callback"
      ).foreach(uri => OAuthSettings.validRedirect(uri) mustBe true)
    }
    "refuse other http callbacks and loopbacks without a port, path or clean URI" in {
      Seq(
        "http://localhost:8111/oauth_authorization",
        "http://127.0.0.2:8111/oauth_authorization",
        "http://example.org:8111/oauth_authorization",
        "http://127.0.0.1/oauth_authorization",
        "http://127.0.0.1:8111",
        "http://127.0.0.1:8111/cb?x=1",
        "http://127.0.0.1:8111/cb#x",
        "http://user@127.0.0.1:8111/cb",
        "http://127.0.0.1.example.org:8111/cb",
        "ftp://127.0.0.1:8111/cb"
      ).foreach(uri => OAuthSettings.validRedirect(uri) mustBe false)
    }
  }

  "OAuthSettings.clients" should {
    val base = Map(
      "oauthProvider.enabled"     -> true,
      "oauthProvider.callbackUri" -> "https://backend.example/oauth/callback"
    )
    def client(scopes: Seq[String]) =
      Map(
        "id"           -> "app",
        "name"         -> "App",
        "redirectUris" -> Seq("org.example.app:/cb"),
        "scopes"       -> scopes
      )
    "read a configured editor client" in {
      val settings = new OAuthSettings(
        Configuration.from(
          base + ("oauthProvider.clients" -> Seq(
            client(Seq("tasks:read", "tasks:write", "tasks:edit"))
          ))
        )
      )
      settings.clients("app").scopes mustBe Set("tasks:read", "tasks:write", "tasks:edit")
    }
    "refuse invalid client scopes at startup" in {
      an[IllegalArgumentException] must be thrownBy new OAuthSettings(
        Configuration.from(base + ("oauthProvider.clients" -> Seq(client(Seq("tasks:write")))))
      )
    }
    "be empty while the provider is off" in {
      new OAuthSettings(
        Configuration.from(
          Map("oauthProvider.enabled" -> false, "oauthProvider.clients" -> Seq(client(Seq("x"))))
        )
      ).clients mustBe empty
    }
  }
}
