package nl.michelbijnen.ctf.authorization.web;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

import static org.springframework.web.reactive.function.server.RequestPredicates.*;

@Configuration
public class Router {
    private final MediaType json = MediaType.APPLICATION_JSON;

    @Bean
    public RouterFunction<ServerResponse> authEndpoint (AuthHandler handler){
        return RouterFunctions
                .route(POST("/auth/signup").and(accept(json)), handler::signup)
                .andRoute(POST("/auth/login").and(accept(json)), handler::login);
    }

    @Bean
    public RouterFunction<ServerResponse> protectedEndpoint (AuthHandler handler,
                                                             AuthFunction authFunction){
        return RouterFunctions
                .route(POST("/checktoken").and(accept(json)), handler::checkToken)
                .filter(authFunction::filter);
    }
}
