package nl.michelbijnen.ctf.authorization.managers;

import nl.michelbijnen.ctf.authorization.models.CheckTokenResponse;
import reactor.core.publisher.Mono;

public interface TokenManager {

    String issueToken(String userId, String role);

    Mono<CheckTokenResponse> parse(String token);
}
