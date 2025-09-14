package sample.secure;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import jakarta.persistence.*;
import java.util.List;

@RestController
public class SafeSQLi001 {

    @PersistenceContext
    private EntityManager em;

    // SAFE: parameterized JPQL
    @GetMapping("/owners-safe")
    public List<?> ownersSafe(@RequestParam String lastName) {
        String jpql = "SELECT o FROM Owner o WHERE o.lastName = :ln";
        return em.createQuery(jpql)
                 .setParameter("ln", lastName)
                 .getResultList();
    }
}
