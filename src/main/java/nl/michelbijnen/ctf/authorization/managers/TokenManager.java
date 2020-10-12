package nl.michelbijnen.ctf.authorization.managers;

import reactor.core.publisher.Mono;

public interface TokenManager {

    String issueToken(String userId, String role);

    Mono<String> parse(String token);
}
