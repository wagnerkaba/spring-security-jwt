package com.wagner.springsecurityjwt.controller;

import com.wagner.springsecurityjwt.models.AuthenticationRequest;
import com.wagner.springsecurityjwt.models.AuthenticationResponse;
import com.wagner.springsecurityjwt.services.MyUserDetailsService;
import com.wagner.springsecurityjwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    //Na classe SecurityConfigurer existe um @Bean de AuthenticationManager
    //Para mais informações, vide: https://www.youtube.com/watch?v=X80nJ5T7YpE aos 26 minutos
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Autowired
    private JwtUtil jwtTokenUtil;

    @RequestMapping({"/hello"})
    public String hello(){
        return "Hello world";
    }

    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception{

        // tenta autenticar o usuário enviado através do @RequestBody
        // se a autenticação falhar, lança uma BadCredentialsException
        try {


            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword())
            );
        } catch (BadCredentialsException e){
            throw new Exception("Incorrect username or password", e);
        }

        // o usuário foi autenticado, então agora é preciso criar o token JWT
        // Para criar o token JWT, é preciso uma instância de userDetails
        final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());

        // cria um token JWT com o objeto userDetails
        final String jwt = jwtTokenUtil.generateToken(userDetails);

        // retorna otoken JWT para o usuário
        return ResponseEntity.ok(new AuthenticationResponse(jwt));

    }

}
