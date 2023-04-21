package com.openblocks.api.authentication.request.oauth2.request;

import com.openblocks.api.authentication.request.AuthException;
import com.openblocks.api.authentication.request.oauth2.OAuth2RequestContext;
import com.openblocks.api.authentication.request.oauth2.Oauth2Source;
import com.openblocks.domain.user.model.AuthToken;
import com.openblocks.domain.user.model.AuthUser;
import com.openblocks.sdk.auth.KeycloakAuthConfig;
import com.openblocks.sdk.auth.Oauth2SimpleAuthConfig;
import com.openblocks.sdk.util.JsonUtils;
import com.openblocks.sdk.webclient.WebClientBuildHelper;
import org.apache.commons.collections4.MapUtils;
import org.apache.http.client.utils.URIBuilder;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

public class KeycloakRequest extends AbstractOauth2Request<Oauth2SimpleAuthConfig> implements Oauth2Source {

    public KeycloakRequest(KeycloakAuthConfig config) {
        super(config, null);
        source = this;
    }

    @Override
    protected Mono<AuthToken> getAuthToken(OAuth2RequestContext context) {
        URI uri;
        try {
            uri = new URIBuilder(source.accessToken())
                    .build();
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("code", context.getCode());
        formData.add("client_id", config.getClientId());
        formData.add("client_secret", config.getClientSecret());
        formData.add("redirect_uri", ((KeycloakAuthConfig)config).getRedirectUri());
        formData.add("grant_type", "authorization_code");
        return WebClientBuildHelper.builder()
                .systemProxy()
                .build()
                .post()
                .uri(uri)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(formData))
                .exchangeToMono(response -> response.bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {
                }))
                .flatMap(map -> {
                    if (map.containsKey("error") || map.containsKey("error_description")) {
                        throw new AuthException(JsonUtils.toJson(map));
                    }
                    AuthToken authToken = AuthToken.builder()
                            .accessToken(MapUtils.getString(map, "access_token"))
                            .expireIn(MapUtils.getIntValue(map, "expires_in"))
                            .build();
                    return Mono.just(authToken);
                });
    }

    @Override
    protected Mono<AuthUser> getAuthUser(AuthToken authToken) {
        return WebClientBuildHelper.builder()
                .systemProxy()
                .build()
                .post()
                .uri(source.userInfo())
                .header("Authorization", "Bearer " + authToken.getAccessToken())
                .exchangeToMono(response -> response.bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {
                }))
                .flatMap(map -> {
                    if (map.containsKey("error") || map.containsKey("error_description")) {
                        throw new AuthException(JsonUtils.toJson(map));
                    }
                    AuthUser authUser = AuthUser.builder()
                            .uid(MapUtils.getString(map, "sub"))
                            .username(MapUtils.getString(map, "name"))
                            .avatar(MapUtils.getString(map, "picture"))
                            .rawUserInfo(map)
                            .build();
                    return Mono.just(authUser);
                });
    }

    @Override
    public String accessToken() {
        return ((KeycloakAuthConfig)config).getAccessTokenUri();
    }

    @Override
    public String userInfo() {
        return ((KeycloakAuthConfig)config).getUserInfoUri();
    }
}
