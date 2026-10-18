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
  }
}
