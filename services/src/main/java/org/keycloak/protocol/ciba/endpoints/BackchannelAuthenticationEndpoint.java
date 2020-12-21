package org.keycloak.protocol.ciba.endpoints;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Time;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.ciba.CIBAAuthReqId;
import org.keycloak.protocol.ciba.CIBAConstants;
import org.keycloak.protocol.ciba.CIBAErrorCodes;
import org.keycloak.protocol.ciba.decoupledauthn.DecoupledAuthenticationProvider;
import org.keycloak.protocol.ciba.endpoints.request.BackchannelAuthenticationRequest;
import org.keycloak.protocol.ciba.endpoints.request.BackchannelAuthenticationRequestParserProcessor;
import org.keycloak.protocol.ciba.resolvers.CIBALoginUserResolver;
import org.keycloak.protocol.ciba.utils.CIBAAuthReqIdParser;
import org.keycloak.protocol.ciba.utils.EarlyAccessBlocker;
import org.keycloak.protocol.ciba.utils.EarlyAccessBlockerParser;
import org.keycloak.protocol.oidc.utils.AuthorizeClientUtil;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.Cors;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.POST;
import javax.ws.rs.core.*;
import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

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
        cors = Cors.add(httpRequest).auth().allowedMethods("POST").auth().exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS);
        formParams = httpRequest.getDecodedFormParameters();
        dumpMultivaluedMap(formParams);
        checkSsl();
        checkRealm();
        checkClient();

        BackchannelAuthenticationRequest request = BackchannelAuthenticationRequestParserProcessor.parseRequest(event, session, client, formParams);
        validateRequest(request);

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
            EarlyAccessBlockerParser.persistEarlyAccessBlocker(session, throttlingId, earlyAccessBlockerData, interval);
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

    private void validateRequest(BackchannelAuthenticationRequest request) {

        String scope =  request.getScope();
        if (scope == null)
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "missing parameter : scope", Response.Status.BAD_REQUEST);

        logger.debug("  scope = " + request.getScope());

        String authRequestedUserHint = realm.getCIBAPolicy().getAuthRequestedUserHint();
        logger.debug("  authRequestedUserHint = " + authRequestedUserHint);
        String userHint;
        if (authRequestedUserHint.equals(CIBAConstants.LOGIN_HINT)) {
            userHint = request.getLoginHint();
            if (userHint == null)
                throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "missing parameter : login_hint", Response.Status.BAD_REQUEST);
            logger.debug("  login_hint = " + request.getLoginHint());
        } else if (authRequestedUserHint.equals(CIBAConstants.ID_TOKEN_HINT)) {
            userHint = request.getIdTokenHint();
            if (userHint == null)
                throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "missing parameter : id_token_hint", Response.Status.BAD_REQUEST);
            logger.debug("  id_token_hint = " + request.getIdTokenHint());
        } else if (authRequestedUserHint.equals(CIBAConstants.LOGIN_HINT_TOKEN)) {
            userHint = request.getLoginHintToken();
            if (userHint == null)
                throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "missing parameter : login_hint_token", Response.Status.BAD_REQUEST);
            logger.debug("  login_hint_token = " + request.getLoginHintToken());
        } else {
            logger.error("CIBA invalid Authentication Requested User Hint.");
            throw new ErrorResponseException(CIBAErrorCodes.UNKNOWN_USER_ID, "no user identifier in request", Response.Status.BAD_REQUEST);
        }

        String bindingMessage = request.getBindingMessage();
        if (bindingMessage != null) {
            logger.debug("  binding_message = " + request.getBindingMessage());
        }

        String userCode = request.getUserCode();
        if (userCode != null) {
            logger.debug("  user_code = " + request.getUserCode());
        }

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
        } else if (authRequestedUserHint.equals(CIBAConstants.ID_TOKEN_HINT)) {
            user = resolver.getUserFromIdTokenHint(request.getIdTokenHint());
        } else if (authRequestedUserHint.equals(CIBAConstants.LOGIN_HINT_TOKEN)) {
            user = resolver.getUserFromLoginHintToken(request.getLoginHintToken());
        } else {
            throw new RuntimeException("CIBA invalid Authentication Requested User Hint.");
        }
        if (user == null)
            throw new CorsErrorResponseException(cors, CIBAErrorCodes.UNKNOWN_USER_ID, "no user found", Response.Status.BAD_REQUEST);
        if (!user.isEnabled())
            throw new CorsErrorResponseException(cors, CIBAErrorCodes.UNKNOWN_USER_ID, "user deactivated", Response.Status.BAD_REQUEST);
        return user;
    }

    private void dumpMultivaluedMap(MultivaluedMap<String, String> params) {
        Set<String> keys = params.keySet();
        keys.forEach(i -> {
            logger.info("key = " + i);
            params.get(i).forEach(j -> logger.info("value = " + j));
        });
    }

}
