package nl.michelbijnen.ctf.authorization.repositories;

import nl.michelbijnen.ctf.authorization.models.Team;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TeamRepository extends JpaRepository<Team, String> {
    Optional<Team> findTeamByName(String teamName);
}
