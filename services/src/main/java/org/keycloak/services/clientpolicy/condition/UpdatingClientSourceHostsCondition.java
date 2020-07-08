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

package org.keycloak.services.clientpolicy.condition;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;

public class UpdatingClientSourceHostsCondition implements ClientPolicyConditionProvider {

    private static final Logger logger = Logger.getLogger(UpdatingClientSourceHostsCondition.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public UpdatingClientSourceHostsCondition(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    @Override
    public String getName() {
        return componentModel.getName();
    }

    @Override
    public String getProviderId() {
        return componentModel.getProviderId();
    }

    @Override
    public boolean isSatisfiedOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        switch (context.getEvent()) {
        case REGISTER:
        case UPDATE:
            return isHostMatched();
        default:
            throw new ClientPolicyException(ClientPolicyConditionProvider.SKIP_EVALUATION, "");
        }
    }
    
    private boolean isHostMatched() {
        String host = session.getContext().getRequestHeaders().getHeaderString("Host");

        ClientPolicyLogger.log(logger, "host = " + host);
        componentModel.getConfig().get(UpdatingClientSourceHostsConditionFactory.HOSTS).stream().forEach(i -> ClientPolicyLogger.log(logger, "host expected = " + i));

        boolean isMatched = componentModel.getConfig().get(UpdatingClientSourceHostsConditionFactory.HOSTS).stream().anyMatch(i -> i.equals(host));
        if(isMatched) {
            ClientPolicyLogger.log(logger, "host matched.");
        } else {
            ClientPolicyLogger.log(logger, "host unmatched.");
        }
        return isMatched;
    }
 
}
