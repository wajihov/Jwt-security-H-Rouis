package com.rouis.security.config;

import com.rouis.security.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor //creer constructeur avec les attributs FINAL
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final  UserDetailsService userDetailsService;
    private final JwtService jwtService ;
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        //le bearer token se trouve dans le Header du request , donc on va le picker du header
        final String authHeader = request.getHeader("Authorization");
        //jwt c est le token
        final String jwt;
        final String userEmail;

        if(authHeader==null || !authHeader.startsWith("Bearer ")){
            //on passe au deuxieme filtre
            filterChain.doFilter(request, response);
            //on abondonne tout
            return;
        }
        //Extract the token
        jwt=authHeader.substring(7);
        //extract the user email from jwt token---->j ai besoin d dppeler une classe
        //qui manimule les tokens c est la classe JwtService
        //JwtService c est la clsse qui me permet d extraire les infos qui se trouvent dans le token

        userEmail=jwtService.extractUserName(jwt);
        // lorsque SecurityContextHolder.getContext().getAuthentication()==null  cela veut dire que l utulisateur n est
        //pas connecté encore
        if(userEmail!=null && SecurityContextHolder.getContext().getAuthentication()==null){
            UserDetails userDetails=this.userDetailsService.loadUserByUsername(userEmail);
           //si le token est valid
            if(jwtService.isTokenValid(jwt, userDetails)){//update the security context and send request to distatcher

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                //update security context holder
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
            filterChain.doFilter(request, response);
        }
           // UserDetails userDetails=this

    }
}
