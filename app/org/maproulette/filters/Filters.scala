/*
 * Copyright (C) 2020 MapRoulette contributors (see CONTRIBUTORS.md).
 * Licensed under the Apache License, Version 2.0 (see LICENSE).
 */
package org.maproulette.filters

import javax.inject.Inject
import play.api.http.DefaultHttpFilters
import play.filters.cors.CORSFilter
import play.filters.gzip.GzipFilter

/**
  * @author cuthbertm
  */
class Filters @Inject() (
    routeHeaderFilter: RouteHeaderFilter,
    corsFilter: CORSFilter,
    gzipFilter: GzipFilter,
    httpLoggingFilter: HttpLoggingFilter,
    bearerFilter: org.maproulette.auth.oauth.OAuthBearerFilter
) extends DefaultHttpFilters(
      routeHeaderFilter,
      corsFilter,
      gzipFilter,
      httpLoggingFilter,
      bearerFilter
    )
