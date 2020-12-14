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
package org.keycloak.testsuite.ciba;

public class DecoupledAuthenticationRequest {

    private String decoupledAuthId;
    private String userInfo;
    private boolean isConsentRequred;
    private String scope;
    private String defaultClientScope;
    private String bindingMessage;

    public String getDecoupledAuthId() {
        return decoupledAuthId;
    }

    public void setDecoupledAuthId(String decoupledAuthId) {
        this.decoupledAuthId = decoupledAuthId;
    }

    public String getUserInfo() {
        return userInfo;
    }

    public void setUserInfo(String userInfo) {
        this.userInfo = userInfo;
    }

    public boolean isConsentRequired() {
        return isConsentRequred;
    }

    public void setConsentRequired(boolean isConsentRequred) {
        this.isConsentRequred = isConsentRequred;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getDefaultClientScope() {
        return defaultClientScope;
    }

    public void setDefaultClientScope(String defaultClientScope) {
        this.defaultClientScope = defaultClientScope;
    }

    public String getBindingMessage() {
        return bindingMessage;
    }

    public void setBindingMessage(String bindingMessage) {
        this.bindingMessage = bindingMessage;
    }
}
