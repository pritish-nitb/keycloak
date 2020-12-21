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

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.util.JsonSerialization;

import java.util.HashSet;
import java.util.Set;

class BackchannelAuthenticationRequestObjectParser extends BackchannelAuthenticationRequestParser {

    private final JsonNode requestParams;

    public BackchannelAuthenticationRequestObjectParser(KeycloakSession session, String requestObject, ClientModel client) throws Exception {
        JWSInput input = new JWSInput(requestObject);
        JWSHeader header = input.getHeader();
        Algorithm headerAlgorithm = header.getAlgorithm();

        Algorithm requestedSignatureAlgorithm = OIDCAdvancedConfigWrapper.fromClientModel(client).getRequestObjectSignatureAlg();

        if (headerAlgorithm == null) {
            throw new RuntimeException("Request object signed algorithm not specified");
        }
        if (requestedSignatureAlgorithm != null && requestedSignatureAlgorithm != headerAlgorithm) {
            throw new RuntimeException("Request object signed with different algorithm than client requested algorithm");
        }

        if (header.getAlgorithm() == Algorithm.none) {
            this.requestParams = JsonSerialization.readValue(input.getContent(), JsonNode.class);
        } else {
            this.requestParams = session.tokens().decodeClientJWT(requestObject, client, JsonNode.class);
            if (this.requestParams == null) {
                throw new RuntimeException("Failed to verify signature on 'request' object");
            }
        }
        session.setAttribute(BackchannelAuthenticationRequestParser.AUTHZ_REQUEST_OBJECT, requestParams);
    }

    @Override
    protected String getParameter(String paramName) {
        JsonNode val = this.requestParams.get(paramName);
        if (val == null) {
            return null;
        } else if (val.isValueNode()) {
            return val.asText();
        } else {
            return val.toString();
        }
    }

    @Override
    protected Set<String> keySet() {
        HashSet<String> keys = new HashSet<>();
        requestParams.fieldNames().forEachRemaining(keys::add);
        return keys;
    }

}
