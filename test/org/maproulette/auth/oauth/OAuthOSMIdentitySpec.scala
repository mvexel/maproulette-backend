package org.maproulette.auth.oauth

import org.maproulette.Config
import org.maproulette.framework.model.User
import org.mockito.ArgumentCaptor
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.{never, verify, when}
import org.scalatestplus.mockito.MockitoSugar
import org.scalatestplus.play.PlaySpec
import play.api.libs.ws.{WSClient, WSRequest, WSResponse}
import play.api.test.Helpers._
import scala.concurrent.{ExecutionContext, Future}

class OAuthOSMIdentitySpec extends PlaySpec with MockitoSugar {
  private implicit val ec: ExecutionContext = ExecutionContext.global
  private val xml =
    """<osm><user id="42" display_name="Mapper" account_created="2020-01-01T00:00:00Z"><description>Mapper</description></user></osm>"""
  private val credential = "upstream-secret-never-stored"

  private def fixture(status: Int, body: String) = {
    val ws          = mock[WSClient]
    val config      = mock[Config]
    val provisioner = mock[OAuthUserProvisioner]
    val request     = mock[WSRequest]
    val response    = mock[WSResponse]
    when(config.getOSMServer).thenReturn("https://osm.example")
    when(ws.url("https://osm.example/api/0.6/user/details")).thenReturn(request)
    when(request.withFollowRedirects(false)).thenReturn(request)
    when(request.withHttpHeaders("Authorization" -> s"Bearer $credential")).thenReturn(request)
    when(request.get()).thenReturn(Future.successful(response))
    when(response.status).thenReturn(status)
    when(response.body).thenReturn(body)
    (new OAuthOSMIdentity(ws, config, provisioner), provisioner, request)
  }

  "OAuth OSM identity" should {
    "verify upstream identity and strip the upstream token before provisioning" in {
      val (identity, provisioner, request) = fixture(200, xml)
      val existing                         = User.superUser.copy(id = 123)
      when(provisioner.resolve(any[User])).thenReturn(existing)
      await(identity.resolve(credential)) mustBe existing
      val profile = ArgumentCaptor.forClass(classOf[User])
      verify(provisioner).resolve(profile.capture())
      profile.getValue.osmProfile.id mustBe 42
      profile.getValue.osmProfile.requestToken mustBe ""
      verify(request).withFollowRedirects(false)
    }
    "fail closed on upstream failures without provisioning or exposing response content" in {
      val (identity, provisioner, _) = fixture(401, "secret-response")
      val error                      = intercept[IllegalArgumentException](await(identity.resolve(credential)))
      error.getMessage mustBe "OSM identity verification failed"
      verify(provisioner, never()).resolve(any[User])
    }
    "reject malformed or non-human identities" in {
      Seq("invalid-xml", xml.replace("id=\"42\"", "id=\"-1\"")).foreach { body =>
        val (identity, provisioner, _) = fixture(200, body)
        intercept[IllegalArgumentException](await(identity.resolve(credential)))
        verify(provisioner, never()).resolve(any[User])
      }
    }
  }
}
