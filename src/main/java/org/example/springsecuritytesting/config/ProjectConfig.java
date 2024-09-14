package org.example.springsecuritytesting.config;

import org.springframework.cglib.proxy.NoOp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ProjectConfig {

    private final AuthenticationProvider provider;

    ProjectConfig(CustomAuthenticationProvider provider) {
        this.provider = provider;
    }

    @Bean
    SecurityFilterChain configure(HttpSecurity http)
            throws Exception{

        UserDetails user = User.withUsername("mary")
                        .password("12345")
                        .authorities("read")
                        .build();
        var userDetailsService = new InMemoryUserDetailsManager(user);
        http.userDetailsService(userDetailsService);
        http.httpBasic(Customizer.withDefaults());
        http.authenticationProvider(provider);
        http.authorizeHttpRequests(
                c->c.anyRequest().authenticated()
        );
        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
