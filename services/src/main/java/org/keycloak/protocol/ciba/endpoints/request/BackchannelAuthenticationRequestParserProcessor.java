/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.protocol.ciba.endpoints.request;

import org.keycloak.common.util.StreamUtil;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.ciba.CIBAConstants;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.services.ErrorPageException;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.InputStream;

public class BackchannelAuthenticationRequestParserProcessor {

    public static BackchannelAuthenticationRequest parseRequest(EventBuilder event, KeycloakSession session, ClientModel client, MultivaluedMap<String, String> requestParams) {
        try {
            BackchannelAuthenticationRequest request = new BackchannelAuthenticationRequest();

            BackchannelAuthenticationQueryStringParser parser = new BackchannelAuthenticationQueryStringParser(requestParams);
            parser.parseRequest(request);

            if (parser.getInvalidRequestMessage() != null) {
                request.invalidRequestMessage = parser.getInvalidRequestMessage();
                return request;
            }

            String requestParam = requestParams.getFirst(CIBAConstants.REQUEST);
            String requestUriParam = requestParams.getFirst(CIBAConstants.REQUEST_URI);

            if (requestParam != null && requestUriParam != null) {
                throw new RuntimeException("Illegal to use both 'request' and 'request_uri' parameters together");
            }

            String requestObjectRequired = OIDCAdvancedConfigWrapper.fromClientModel(client).getRequestObjectRequired();

            if (OIDCConfigAttributes.REQUEST_OBJECT_REQUIRED_REQUEST_OR_REQUEST_URI.equals(requestObjectRequired)
                    && requestParam == null && requestUriParam == null) {
                throw new RuntimeException("Client is required to use 'request' or 'request_uri' parameter.");
            } else if (OIDCConfigAttributes.REQUEST_OBJECT_REQUIRED_REQUEST.equals(requestObjectRequired)
                    && requestParam == null) {
                throw new RuntimeException("Client is required to use 'request' parameter.");
            } else if (OIDCConfigAttributes.REQUEST_OBJECT_REQUIRED_REQUEST_URI.equals(requestObjectRequired)
                    && requestUriParam == null) {
                throw new RuntimeException("Client is required to use 'request_uri' parameter.");
            }

            if (requestParam != null) {
                new BackchannelAuthenticationRequestObjectParser(session, requestParam, client).parseRequest(request);
            } else if (requestUriParam != null) {
                try (InputStream is = session.getProvider(HttpClientProvider.class).get(requestUriParam)) {
                    String retrievedRequest = StreamUtil.readString(is);
                    new BackchannelAuthenticationRequestObjectParser(session, retrievedRequest, client).parseRequest(request);
                }
            }

            return request;

        } catch (Exception e) {
            ServicesLogger.LOGGER.invalidRequest(e);
            event.error(Errors.INVALID_REQUEST);
            throw new ErrorPageException(session, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
        }
    }


}