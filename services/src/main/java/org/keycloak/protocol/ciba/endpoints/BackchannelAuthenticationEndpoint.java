/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates
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
package org.keycloak.protocol.ciba.endpoints;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;

import javax.ws.rs.POST;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.Profile;
import org.keycloak.common.util.Time;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.CIBAPolicy;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.ciba.CIBAAuthReqId;
import org.keycloak.protocol.ciba.CIBAConstants;
import org.keycloak.protocol.ciba.CIBAErrorCodes;
import org.keycloak.protocol.ciba.decoupledauthn.DecoupledAuthenticationProvider;
import org.keycloak.protocol.ciba.endpoints.request.BackchannelAuthenticationRequest;
import org.keycloak.protocol.ciba.resolvers.CIBALoginUserResolver;
import org.keycloak.protocol.ciba.utils.CIBAAuthReqIdParser;
import org.keycloak.protocol.ciba.utils.EarlyAccessBlocker;
import org.keycloak.protocol.ciba.utils.EarlyAccessBlockerParser;
import org.keycloak.protocol.oidc.utils.AuthorizeClientUtil;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.Cors;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.ProfileHelper;

import com.fasterxml.jackson.databind.node.ObjectNode;

public class BackchannelAuthenticationEndpoint {

    private static final Logger logger = Logger.getLogger(BackchannelAuthenticationEndpoint.class);

    private MultivaluedMap<String, String> formParams;

    private RealmModel realm;

    private ClientModel client;
    private Map<String, String> clientAuthAttributes;

    private EventBuilder event;

    @Context
    private HttpHeaders headers;
    @Context
    private HttpRequest httpRequest;
    @Context
    private HttpResponse httpResponse;
    @Context
    private KeycloakSession session;
    @Context
    private ClientConnection clientConnection;

    private Cors cors;

    private CIBAPolicy policy;

    public BackchannelAuthenticationEndpoint(RealmModel realm, EventBuilder event) {
        this.realm = realm;
        this.event = event;
        event.event(EventType.LOGIN);
        policy = realm.getCIBAPolicy();
    }

    @POST
    public Response processGrantRequest() {
        ProfileHelper.requireFeature(Profile.Feature.CIBA);

        cors = Cors.add(httpRequest).auth().allowedMethods("POST").auth().exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS);
        formParams = httpRequest.getDecodedFormParameters();
        BackchannelAuthenticationRequest request = parseRequest(formParams);

        checkSsl();
        checkRealm();
        checkClient();
        UserModel user = checkUser(request);
        logger.info(" client_id = " + client.getClientId());
        logger.info(" consent required = " + client.isConsentRequired());

        MultivaluedMap<String, Object> outputHeaders = httpResponse.getOutputHeaders();
        outputHeaders.putSingle("Cache-Control", "no-store");
        outputHeaders.putSingle("Pragma", "no-cache");

        // create Auth Result's ID
        // Auth Result stands for authentication result by AD(Authentication Device).
        // By including it in Auth Req ID, keycloak can find Auth Result corresponding to Auth Req ID on Token Endpoint.
        String authResultId = UUID.randomUUID().toString();

        // create auth_req_id and store Auth Req ID as its representation
        // UserSession's ID will become userSessionIdWillBeCreated which make it easy for searching UserSession on TokenEndpoint afterwards
        String userSessionIdWillBeCreated = getUserSessionIdWillBeCreated();

        int interval = policy.getInterval();
        String throttlingId = null;
        if (interval > 0) throttlingId = UUID.randomUUID().toString();
        CIBAAuthReqId authReqIdJwt = new CIBAAuthReqId();
        authReqIdJwt.id(KeycloakModelUtils.generateId());
        authReqIdJwt.setScope(request.getScope());
        authReqIdJwt.setSessionState(userSessionIdWillBeCreated);
        authReqIdJwt.setAuthResultId(authResultId);
        if (throttlingId != null) authReqIdJwt.setThrottlingId(throttlingId);
        authReqIdJwt.issuedNow();
        authReqIdJwt.issuer(Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        authReqIdJwt.audience(authReqIdJwt.getIssuer());
        authReqIdJwt.subject(user.getId());
        authReqIdJwt.exp(Long.valueOf(Time.currentTime() + policy.getExpiresIn()));
        authReqIdJwt.issuedFor(client.getClientId());
        String authReqId = CIBAAuthReqIdParser.persistAuthReqId(session, authReqIdJwt);

        // for access throttling
        if (throttlingId != null) {
            logger.info("  Access throttling : next token request must be after " + interval + " sec.");
            EarlyAccessBlocker earlyAccessBlockerData = new EarlyAccessBlocker(Time.currentTime() + interval, interval);
            EarlyAccessBlockerParser.persistEarlyAccessBlocker(session, throttlingId.toString(), earlyAccessBlockerData, interval);
        }

        DecoupledAuthenticationProvider provider = session.getProvider(DecoupledAuthenticationProvider.class);
        if (provider == null) {
            throw new RuntimeException("CIBA Decoupled Authentication Provider not setup properly.");
        }
        provider.doBackchannelAuthentication(client, request, policy.getExpiresIn(), authResultId, userSessionIdWillBeCreated);

        ObjectNode response = JsonSerialization.createObjectNode();
        response.put(CIBAConstants.AUTH_REQ_ID, authReqId);
        response.put(CIBAConstants.EXPIRES_IN, policy.getExpiresIn());
        if (policy.getInterval() > 0) response.put(CIBAConstants.INTERVAL, policy.getInterval());
        try {
            return Response.ok(JsonSerialization.writeValueAsBytes(response)).type(MediaType.APPLICATION_JSON_TYPE).build();
        } catch (IOException e) {
            throw new RuntimeException("Error creating Backchannel Authentication response.", e);
        }

    }

    private BackchannelAuthenticationRequest parseRequest(MultivaluedMap<String, String> params) {
        BackchannelAuthenticationRequest request = new BackchannelAuthenticationRequest();

        String scope = params.getFirst(CIBAConstants.SCOPE);
        if (scope == null) throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "missing parameter : scope", Response.Status.BAD_REQUEST);
        request.setScope(scope);

        logger.info("  scope = " + request.getScope());

        String authRequestedUserHint = realm.getCIBAPolicy().getAuthRequestedUserHint();
        logger.info("  authRequestedUserHint = " + authRequestedUserHint);
        String userHint = null;
        if (authRequestedUserHint.equals(CIBAConstants.LOGIN_HINT)) {
            userHint = params.getFirst(CIBAConstants.LOGIN_HINT);
            if (userHint == null) throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "missing parameter : login_hint", Response.Status.BAD_REQUEST);
            request.setLoginHint(userHint);
            logger.info("  login_hint = " + request.getLoginHint());
        } else if (authRequestedUserHint.equals(CIBAConstants.ID_TOKEN_HINT)) {
            userHint = params.getFirst(CIBAConstants.ID_TOKEN_HINT);
            if (userHint == null) throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "missing parameter : id_token_hint", Response.Status.BAD_REQUEST);
            request.setIdTokenHint(userHint);
        } else if (authRequestedUserHint.equals(CIBAConstants.LOGIN_HINT_TOKEN)) {
            userHint = params.getFirst(CIBAConstants.LOGIN_HINT_TOKEN);
            if (userHint == null) throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "missing parameter : login_hint_token", Response.Status.BAD_REQUEST);
            request.setIdTokenHint(userHint);
        } else {
            throw new RuntimeException("CIBA invalid Authentication Requested User Hint.");
        }

        String bindingMessage = params.getFirst(CIBAConstants.BINDING_MESSAGE);
        if (bindingMessage != null) {
            request.setBindingMessage(bindingMessage);
            logger.info("  binding_message = " + request.getBindingMessage());
        }

        return request;
    }

    private String getUserSessionIdWillBeCreated() {
        return KeycloakModelUtils.generateId();
    }

    private void checkSsl() {
        if (!session.getContext().getUri().getBaseUri().getScheme().equals("https") && realm.getSslRequired().isRequired(clientConnection)) {
            throw new CorsErrorResponseException(cors.allowAllOrigins(), OAuthErrorException.INVALID_REQUEST, "HTTPS required", Response.Status.FORBIDDEN);
        }
    }

    private void checkRealm() {
        if (!realm.isEnabled()) {
            throw new CorsErrorResponseException(cors.allowAllOrigins(), "access_denied", "Realm not enabled", Response.Status.FORBIDDEN);
        }
    }

    private void checkClient() {
        AuthorizeClientUtil.ClientAuthResult clientAuth = AuthorizeClientUtil.authorizeClient(session, event);
        client = clientAuth.getClient();
        clientAuthAttributes = clientAuth.getClientAuthAttributes();

        cors.allowedOrigins(session, client);

        if (client.isBearerOnly()) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_CLIENT, "Bearer-only not allowed", Response.Status.BAD_REQUEST);
        }
    }

    private UserModel checkUser(BackchannelAuthenticationRequest request) {
        CIBALoginUserResolver resolver = session.getProvider(CIBALoginUserResolver.class);
        if (resolver == null) {
            throw new RuntimeException("CIBA Login User Resolver not setup properly.");
        }
        String authRequestedUserHint = realm.getCIBAPolicy().getAuthRequestedUserHint();
        UserModel user = null;
        if (authRequestedUserHint.equals(CIBAConstants.LOGIN_HINT)) {
            user = resolver.getUserFromLoginHint(request.getLoginHint());
        // TODO : other login hint methods support
        //} else if (authRequestedUserHint.equals(CIBAConstants.ID_TOKEN_HINT)) {
        //    user = resolver.getUserFromLoginHint(request.getIdTokenHint());
        //} else if (authRequestedUserHint.equals(CIBAConstants.LOGIN_HINT_TOKEN)) {
        //    user = resolver.getUserFromLoginHint(request.getLoginHintToken());
        } else {
            throw new RuntimeException("CIBA invalid Authentication Requested User Hint.");
        }
        if (user == null)
            throw new CorsErrorResponseException(cors, CIBAErrorCodes.UNKNOWN_USER_ID, "no user found", Response.Status.BAD_REQUEST);
        if (!user.isEnabled())
            throw new CorsErrorResponseException(cors, CIBAErrorCodes.UNKNOWN_USER_ID, "user deactivated", Response.Status.BAD_REQUEST);
        return user;
    }
}
