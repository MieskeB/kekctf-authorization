package nl.michelbijnen.ctf.authorization.web;

import lombok.RequiredArgsConstructor;
import nl.michelbijnen.ctf.authorization.errors.InvalidTokenException;
import nl.michelbijnen.ctf.authorization.errors.LoginDeniedException;
import nl.michelbijnen.ctf.authorization.models.*;
import nl.michelbijnen.ctf.authorization.services.AuthService;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyExtractor;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class AuthHandler {
    private MediaType json = MediaType.APPLICATION_JSON;
    private final AuthService service;

    public Mono<ServerResponse> signup (ServerRequest request){
        Mono<SignupRequest> body = request.bodyToMono(SignupRequest.class);
        Mono<SignupResponse> result = body.flatMap(service::signup);
        return result.flatMap(data -> ServerResponse.ok().contentType(json).bodyValue(data))
                .onErrorResume(error -> ServerResponse.badRequest().build());
    }

    public Mono<ServerResponse> login (ServerRequest request){
        Mono<LoginRequest> body = request.bodyToMono(LoginRequest.class);
        Mono<LoginResponse> result = body.flatMap(service::login);
        return result.flatMap(data -> ServerResponse.ok().contentType(json).bodyValue(data))
                .switchIfEmpty(ServerResponse.notFound().build())
                .onErrorResume(error -> {
                    if (error instanceof LoginDeniedException){
                        return ServerResponse.badRequest().build();
                    }
                    return ServerResponse.status(500).build();
                });
    }

    public Mono<ServerResponse> checkToken(ServerRequest request) {
        CheckTokenRequest checkTokenRequest = new CheckTokenRequest();
        checkTokenRequest.setToken(request.headers().header("Authorization").get(0));
        Mono<CheckTokenRequest> body = Mono.just(checkTokenRequest);
        Mono<CheckTokenResponse> result = body.flatMap(service::checkToken);
        return result.flatMap(data -> ServerResponse.ok().contentType(json).bodyValue(data))
                .onErrorResume(error -> ServerResponse.badRequest().build());
    }
}
