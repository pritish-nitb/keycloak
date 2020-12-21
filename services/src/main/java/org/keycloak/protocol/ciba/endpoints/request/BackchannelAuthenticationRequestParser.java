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

import org.jboss.logging.Logger;
import org.keycloak.protocol.ciba.CIBAConstants;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public abstract class BackchannelAuthenticationRequestParser {

    private static final Logger logger = Logger.getLogger(BackchannelAuthenticationRequestParser.class);

    /**
     * Max number of additional req params copied into client session note to prevent DoS attacks
     *
     */
    public static final int ADDITIONAL_REQ_PARAMS_MAX_MUMBER = 5;

    /**
     * Max size of additional req param value copied into client session note to prevent DoS attacks - params with longer value are ignored
     *
     */
    public static final int ADDITIONAL_REQ_PARAMS_MAX_SIZE = 200;

    public static final String AUTHZ_REQUEST_OBJECT = "ParsedRequestObject";

    /** Set of known protocol GET params not to be stored into additionalReqParams} */
    public static final Set<String> KNOWN_REQ_PARAMS = new HashSet<>();
    static {
        KNOWN_REQ_PARAMS.add(CIBAConstants.CLIENT_NOTIFICATION_TOKEN);
        KNOWN_REQ_PARAMS.add(CIBAConstants.SCOPE);
        KNOWN_REQ_PARAMS.add(CIBAConstants.BINDING_MESSAGE);
        KNOWN_REQ_PARAMS.add(CIBAConstants.LOGIN_HINT_TOKEN);
        KNOWN_REQ_PARAMS.add(CIBAConstants.LOGIN_HINT);
        KNOWN_REQ_PARAMS.add(CIBAConstants.ID_TOKEN_HINT);
        KNOWN_REQ_PARAMS.add(CIBAConstants.USER_CODE);
        KNOWN_REQ_PARAMS.add(CIBAConstants.ACR_VALUES);
        KNOWN_REQ_PARAMS.add(CIBAConstants.REQUESTED_EXPIRY);

        KNOWN_REQ_PARAMS.add(CIBAConstants.REQUEST);
        KNOWN_REQ_PARAMS.add(CIBAConstants.REQUEST_URI);
    }

    public void parseRequest(BackchannelAuthenticationRequest request) {

        request.clientNotificationToken = replaceIfNotNull(request.clientNotificationToken, getParameter(CIBAConstants.CLIENT_NOTIFICATION_TOKEN));
        request.acrValues = replaceIfNotNull(request.acrValues, getParameter(CIBAConstants.ACR_VALUES));
        request.loginHintToken = replaceIfNotNull(request.loginHintToken, getParameter(CIBAConstants.LOGIN_HINT_TOKEN));
        request.idTokenHint = replaceIfNotNull(request.idTokenHint, getParameter(CIBAConstants.ID_TOKEN_HINT));
        request.scope = replaceIfNotNull(request.scope, getParameter(CIBAConstants.SCOPE));
        request.loginHint = replaceIfNotNull(request.loginHint, getParameter(CIBAConstants.LOGIN_HINT));
        request.bindingMessage = replaceIfNotNull(request.bindingMessage, getParameter(CIBAConstants.BINDING_MESSAGE));
        request.userCode = replaceIfNotNull(request.userCode, getParameter(CIBAConstants.USER_CODE));
        request.requestedExpiry = replaceIfNotNull(request.requestedExpiry, getParameter(CIBAConstants.REQUESTED_EXPIRY));

        extractAdditionalReqParams(request.additionalReqParams);
    }

    protected void extractAdditionalReqParams(Map<String, String> additionalReqParams) {
        for (String paramName : keySet()) {
            if (!KNOWN_REQ_PARAMS.contains(paramName)) {
                String value = getParameter(paramName);
                if (value != null && value.trim().isEmpty()) {
                    value = null;
                }
                if (value != null && value.length() <= ADDITIONAL_REQ_PARAMS_MAX_SIZE) {
                    if (additionalReqParams.size() >= ADDITIONAL_REQ_PARAMS_MAX_MUMBER) {
                        logger.debug("Maximal number of additional CIBA params (" + ADDITIONAL_REQ_PARAMS_MAX_MUMBER + ") exceeded, ignoring rest of them!");
                        break;
                    }
                    additionalReqParams.put(paramName, value);
                } else {
                    logger.debug("CIBA Additional param " + paramName + " ignored because value is empty or longer than " + ADDITIONAL_REQ_PARAMS_MAX_SIZE);
                }
            }

        }
    }

    protected <T> T replaceIfNotNull(T previousVal, T newVal) {
        return newVal==null ? previousVal : newVal;
    }

    protected abstract String getParameter(String paramName);

    protected abstract Set<String> keySet();

}
