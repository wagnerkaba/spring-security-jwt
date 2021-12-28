package com.wagner.springsecurityjwt.configuration;

import com.wagner.springsecurityjwt.services.MyUserDetailsService;
import com.wagner.springsecurityjwt.filters.JwtRequestFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfigurer extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyUserDetailsService myUserDetailsService;

    @Autowired
    private JwtRequestFilter jwtRequestFilter;


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        // através do MyUserDetailsService os dados do usuário são carregados
        auth.userDetailsService(myUserDetailsService);

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/authenticate").permitAll()
                .anyRequest().authenticated()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); //não é para salvar sessions, pois estamos usando JWT

        // utiliza o filtro jwtRequestFilter antes de UsernamePasswordAuthenticationFilter ser chamado
        http.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        //TODO This PasswordEncoder is not secure.
        // Instead use an adaptive one way function like BCryptPasswordEncoder, Pbkdf2PasswordEncoder, or SCryptPasswordEncoder.
        // Even better use DelegatingPasswordEncoder which supports password upgrades. There are no plans to remove this support.
        // It is deprecated to indicate that this is a legacy implementation and using it is considered insecure.
        return NoOpPasswordEncoder.getInstance();
    }
}
