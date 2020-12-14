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
package org.keycloak.authentication.authenticators.ciba;

import org.jboss.logging.Logger;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.ciba.CIBAConstants;

public class CIBADecoupledAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(CIBADecoupledAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String userIdField = context.getAuthenticatorConfig().getConfig().get(CIBADecoupledAuthenticatorFactory.DEFAULT_USERID_FIELD);
        if (userIdField == null) userIdField = CIBAConstants.LOGIN_HINT;
        String username = context.getHttpRequest().getDecodedFormParameters().getFirst(userIdField);

        logger.info("username = " + username);
        UserModel user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username);
        if (user == null) {
            logger.info("user model not found");
            context.failure(AuthenticationFlowError.UNKNOWN_USER);
            return;
        }
        logger.infof("user model found. user.getId() = %s, user.getEmail() = %s, user.getUsername() = %s.", user.getId(), user.getEmail(), user.getUsername());
        context.setUser(user);
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public void action(AuthenticationFlowContext context) {

    }

    @Override
    public void close() {

    }


}
