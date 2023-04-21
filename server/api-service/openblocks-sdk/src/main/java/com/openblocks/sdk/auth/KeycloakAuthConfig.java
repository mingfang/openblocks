package com.openblocks.sdk.auth;

import javax.annotation.Nullable;

import lombok.Getter;

import static com.openblocks.sdk.auth.constants.AuthTypeConstants.KEYCLOAK;

@Getter
public class KeycloakAuthConfig extends Oauth2SimpleAuthConfig {
    protected String issuerUri;
    protected String accessTokenUri;
    protected String userInfoUri;
    protected String redirectUri;

    public KeycloakAuthConfig(
            @Nullable String id,
            Boolean enable,
            Boolean enableRegister,
            String source,
            String sourceName,
            String clientId,
            String clientSecret,
            String issuerUri,
            String accessTokenUri,
            String userInfoUri,
            String redirectUri) {
        super(id, enable, enableRegister, source, sourceName, clientId, clientSecret, KEYCLOAK);
        this.issuerUri = issuerUri;
        this.accessTokenUri = accessTokenUri;
        this.userInfoUri = userInfoUri;
        this.redirectUri = redirectUri;
    }

    @Override
    public String getAuthorizeUrl() {
        return issuerUri
                + "?response_type=code"
                + "&client_id=" + clientId
                + "&redirect_uri=" + redirectUri
                + "&access_type=offline"
                + "&scope=openid email profile";
    }
}
