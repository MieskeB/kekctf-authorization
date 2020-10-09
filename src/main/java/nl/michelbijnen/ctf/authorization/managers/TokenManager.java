package nl.michelbijnen.ctf.authorization.managers;

import nl.michelbijnen.ctf.authorization.models.CheckTokenResponse;
import reactor.core.publisher.Mono;

import java.util.List;

public interface TokenManager {

    String issueToken(String userId, List<String> roles);

    Mono<String> parse(String token);
}
