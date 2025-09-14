// CWE-352: CSRF (SECURE)
// Demo: Keep CSRF enabled and use a cookie-based token repository for SPAs.
package demo.secure;

import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
public class SafeCSRF001 {

    @Bean
    public SecurityFilterChain secure(HttpSecurity http) throws Exception {
        http
            // ✅ CSRF enabled (default); explicitly set a token repository for clarity
            .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }
}
