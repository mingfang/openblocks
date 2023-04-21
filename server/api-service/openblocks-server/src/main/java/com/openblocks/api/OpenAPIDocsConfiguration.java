package com.openblocks.api;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.openblocks.sdk.config.CommonConfig;
import org.springframework.beans.factory.annotation.Autowired;

@Configuration
public class OpenAPIDocsConfiguration {
    @Autowired
    private CommonConfig commonConfig;

    @Bean
    public OpenAPI customizeOpenAPI() {
        final String securitySchemeName = commonConfig.getCookieName();
        return new OpenAPI()
                .info(new Info()
                        .title("Openblocks API")
                        .version("1.0"))
                .addServersItem(new Server()
                        .url("/"))
                .addSecurityItem(new SecurityRequirement()
                        .addList(securitySchemeName)).components(new Components()
                        .addSecuritySchemes(
                                securitySchemeName,
                                new SecurityScheme()
                                        .name(securitySchemeName)
                                        .type(SecurityScheme.Type.APIKEY)
                                        .in(SecurityScheme.In.COOKIE)
                        ));
    }
}