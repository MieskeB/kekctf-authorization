package nl.michelbijnen.ctf.authorization.managers;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import nl.michelbijnen.ctf.authorization.errors.InvalidTokenException;
import nl.michelbijnen.ctf.authorization.models.CheckTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Component("TokenManager")
public class TokenManagerImpl implements TokenManager {
    private Logger logger = LoggerFactory.getLogger(this.getClass());

    private RSAKey key;

    public TokenManagerImpl() throws Exception {
        this.key = new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
    }

    @Override
    public String issueToken(String userId, String role) {
        try {
            Date expirationDate = Date.from(Instant.now().plus(1, ChronoUnit.DAYS));

            JWSSigner signer = new RSASSASigner(key);

            JWTClaimsSet.Builder csBuilder = new JWTClaimsSet.Builder();
            csBuilder.subject(userId);
            csBuilder.expirationTime(expirationDate);
            csBuilder.claim("role", role);
            csBuilder.getClaims().forEach((key, value) -> this.logger.debug(key + " " + value));
            JWTClaimsSet cs = csBuilder.build();

            SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), cs);
            signedJWT.sign(signer);
            String token = signedJWT.serialize();
            return token;
        } catch (Exception ex) {
            return null;
        }
    }

    @Override
    public Mono<CheckTokenResponse> parse(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            RSAPublicKey publicKey = key.toRSAPublicKey();
            JWSVerifier verifier = new RSASSAVerifier(publicKey);
            boolean success = signedJWT.verify(verifier);
            if (success) {
                Date expirationDate = signedJWT.getJWTClaimsSet().getExpirationTime();
                if (expirationDate.before(Date.from(Instant.now()))) {
                    return Mono.error(InvalidTokenException::new);
                }
                JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
                String userId = claimsSet.getSubject();
                String role = claimsSet.getClaim("role").toString();

//                Object authorities = signedJWT.getJWTClaimsSet().getClaim("authorities");
//                if (!(authorities instanceof List)) {
//                    return Mono.error(InvalidTokenException::new);
//                }
//                List<String> roles = (List<String>) authorities;

                return Mono.just(new CheckTokenResponse(userId, role));
            } else {
                return Mono.error(InvalidTokenException::new);
            }
        } catch (Exception ex) {
            return Mono.error(InvalidTokenException::new);
        }
    }
}
