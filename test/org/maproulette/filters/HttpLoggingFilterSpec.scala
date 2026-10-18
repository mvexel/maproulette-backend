package org.maproulette.filters

import org.scalatestplus.play.PlaySpec
import play.api.test.FakeRequest

class HttpLoggingFilterSpec extends PlaySpec {
  "HTTP request logging" should {
    "redact sensitive headers" in {
      val request = FakeRequest("GET", "/api/v2/task/123")
        .withHeaders(
          "Authorization" -> "Bearer secret-access",
          "apiKey"        -> "secret-key",
          "Cookie"        -> "secret-cookie",
          "Referer"       -> "https://example.org/?code=secret-code",
          "Accept"        -> "application/json"
        )
      val headers = SafeRequestLog.headers(request)
      headers must not include "secret-"
      headers must include("Authorization=[redacted]")
      headers must include("Accept=application/json")
    }
    "omit OAuth provider query strings" in {
      val request = FakeRequest("GET", "/oauth/callback?code=secret-code&state=secret-state")
      SafeRequestLog.request(request) mustBe "GET /oauth/callback"
    }
    "preserve ordinary route diagnostics" in {
      val request = FakeRequest("GET", "/api/v2/task/123")
      SafeRequestLog.request(request) mustBe request.toString()
    }
  }
}
