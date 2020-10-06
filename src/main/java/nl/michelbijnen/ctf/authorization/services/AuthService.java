package nl.michelbijnen.ctf.authorization.services;

import nl.michelbijnen.ctf.authorization.models.*;
import reactor.core.publisher.Mono;

public interface AuthService {
    Mono<SignupResponse> signup(SignupRequest request);
    Mono<LoginResponse> login(LoginRequest request);
    Mono<CheckTokenResponse> checkToken(CheckTokenRequest request);
    Mono<String> parseToken(String token);
}
