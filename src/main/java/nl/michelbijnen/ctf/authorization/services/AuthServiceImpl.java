package nl.michelbijnen.ctf.authorization.services;

import lombok.AllArgsConstructor;
import nl.michelbijnen.ctf.authorization.errors.AlreadyExistsException;
import nl.michelbijnen.ctf.authorization.errors.LoginDeniedException;
import nl.michelbijnen.ctf.authorization.managers.TokenManager;
import nl.michelbijnen.ctf.authorization.managers.TotpManager;
import nl.michelbijnen.ctf.authorization.models.*;
import nl.michelbijnen.ctf.authorization.repositories.TeamRepository;
import nl.michelbijnen.ctf.authorization.repositories.UserRepository;
import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Component("AuthService")
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private TokenManager tokenManager;
    private TotpManager totpManager;
    private UserRepository userRepository;
    private TeamRepository teamRepository;

    @Override
    public Mono<SignupResponse> signup(SignupRequest request) {

        String username = request.getUsername().trim().toLowerCase();
        String password = request.getPassword();
        String teamName = request.getTeam();
        String salt = BCrypt.gensalt();
        String hash = BCrypt.hashpw(password, salt);
        String secret = this.totpManager.generateSecret();

        Optional<Team> databaseTeamList = this.teamRepository.findTeamByName(teamName);
        Team team;
        if (!databaseTeamList.isPresent()) {
            team = new Team(UUID.randomUUID().toString(), teamName, new ArrayList<>());
            this.teamRepository.save(team);
        } else {
            team = databaseTeamList.get();
        }
        User user = new User(UUID.randomUUID().toString(), username, team, hash, salt, secret, "ROLE_USER");

        Optional<User> optionalUser = this.userRepository.findUserByUsername(username);
        if (optionalUser.isPresent()) {
            this.logger.warn("User with username '" + username + "' tried creating an account, but he already has an account");
            return Mono.error(new AlreadyExistsException());
        }

        this.userRepository.save(user);
        this.logger.info("User with username '" + username + "' created an account");

        String userId = user.getId();
        String token = this.tokenManager.issueToken(userId, user.getRole());
        SignupResponse signupResponse = new SignupResponse(userId, token, secret);
        return Mono.just(signupResponse);
    }

    @Override
    public Mono<LoginResponse> login(LoginRequest request) {
        String username = request.getUsername().trim().toLowerCase();
        String password = request.getPassword();
        String code = request.getCode();

        Optional<User> optionalUser = this.userRepository.findUserByUsername(username);
        if (!optionalUser.isPresent()) {
            this.logger.warn("User with username '" + username + "' tried to log in but he does not exist");
            return Mono.error(new LoginDeniedException());
        }

        User user = optionalUser.get();

        String salt = user.getSalt();
        String secret = user.getSecretKey();
        boolean passwordMatch = BCrypt.hashpw(password, salt).equalsIgnoreCase(user.getHash());

        if (passwordMatch) {
            boolean codeMatched = this.totpManager.validateCode(code, secret);
            if (codeMatched) {
                this.logger.info("User with username '" + username + "' logged in");

                String token = this.tokenManager.issueToken(user.getId(), user.getRole());
                LoginResponse loginResponse = new LoginResponse();
                loginResponse.setToken(token);
                loginResponse.setUserId(user.getId());
                loginResponse.setRole(user.getRole());
                return Mono.just(loginResponse);
            } else {
                this.logger.warn("User with username '" + username + "' tried to log in with wrong 2fa code");
            }
        } else {
            this.logger.warn("User with username '" + username + "' tried to log in with wrong password");
        }
        return Mono.error(LoginDeniedException::new);
    }

    @Override
    public Mono<CheckTokenResponse> checkToken(CheckTokenRequest request) {
        this.logger.debug("Checking token " + request.getToken());
        return this.tokenManager.parse(request.getToken());
    }

    @Override
    public Mono<String> parseToken(String token) {
//        return tokenManager.parse(token);
        return null;
    }
}
