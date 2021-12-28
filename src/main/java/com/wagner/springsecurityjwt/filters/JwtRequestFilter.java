package com.wagner.springsecurityjwt.filters;

import com.wagner.springsecurityjwt.services.MyUserDetailsService;
import com.wagner.springsecurityjwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;




@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    // Este filtro intercepta todos os requests e examina o header para verificar se existe um JWT válido
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {

        // captura o header do request
        final String authorizationHeader = request.getHeader("Authorization");

        String username = null;
        String jwt = null;

        // verifica se o header não é nulo e se contém a palavra "Bearer "
        // O JWT vem sempre depois da palavra "Bearer "
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
            jwt = authorizationHeader.substring(7);
            username = jwtUtil.extractUsername(jwt);
        }

        // verifica se o usuário não é null e se ele já foi autorizado pelo SecurityContextHolder
        // se ainda não foi autorizado no SecurityContextHolder, entra dentro do IF para continuar autorização
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null){

           // carrega o userDetails
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            // verifica se o JWT é válido para o respectivo usuário (userDetails) e se não expirou
            if(jwtUtil.validateToken(jwt, userDetails)){

                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

            }
        }
        // passa o controle para o próximo filtro no FilterChain
        chain.doFilter(request, response);

    }
}
