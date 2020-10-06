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
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;

@Component("TokenManager")
public class TokenManagerImpl implements TokenManager {

    private RSAKey key;

    public TokenManagerImpl() throws Exception {
        this.key = new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
    }

    @Override
    public String issueToken(String userId) {
        try {
            Date expirationDate = Date.from(Instant.now().plus(1, ChronoUnit.DAYS));

            JWSSigner signer = new RSASSASigner(key);
            JWTClaimsSet cs = new JWTClaimsSet.Builder().subject(userId).expirationTime(expirationDate).build();
            SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), cs);
            signedJWT.sign(signer);
            String token = signedJWT.serialize();
            return token;
        } catch (Exception ex){
            return null;
        }
    }

    @Override
    public Mono<String> parse(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            RSAPublicKey publicKey = key.toRSAPublicKey();
            JWSVerifier verifier = new RSASSAVerifier(publicKey);
            boolean success = signedJWT.verify(verifier);
            if (success){
                Date expirationDate = signedJWT.getJWTClaimsSet().getExpirationTime();
                if (expirationDate.before(Date.from(Instant.now()))) {
                    return Mono.error(InvalidTokenException::new);
                }
                String userId = signedJWT.getJWTClaimsSet().getSubject();
                return Mono.just(userId);
            } else {
                return Mono.error(InvalidTokenException::new);
            }
        } catch (Exception ex){
            return Mono.error(InvalidTokenException::new);
        }
    }
}
