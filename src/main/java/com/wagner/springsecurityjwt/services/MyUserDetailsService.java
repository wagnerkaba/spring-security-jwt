package com.wagner.springsecurityjwt.services;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class MyUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {

        // Esta implementação utiliza apenas um usuário fixo
        // Pode-se mudar este método para utilizar usuários de um banco de dados
        // veja exemplo em que usuário é carregado através de um banco de dados: https://github.com/wagnerkaba/spring-security-jpa
        return new User("foo", "foo", new ArrayList<>());
    }
}
