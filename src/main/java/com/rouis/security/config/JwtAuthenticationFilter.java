package com.rouis.security.config;

import com.rouis.security.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
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
@RequiredArgsConstructor // create constructor with attribute's FINAL
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        // the bearer token is in the Header of the request ,we will choose it in the header
        final String authHeader = request.getHeader("Authorization");
        //jwt is the token
        final String jwt;
        final String userEmail;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // we go to the second filter
            filterChain.doFilter(request, response);
            // we give everything away
            return;
        }
        //Extract the token
        jwt = authHeader.substring(7);
        // extract the user email from jwt token ,so I need to call a class
        // which manages the tokens is the JwtService class
        // JwtService is the class that allows me to extract the information that are in the token

        userEmail = jwtService.extractUserName(jwt);
        // when SecurityContextHolder.getContext().getAuthentication()==null,
        // it means that the user is not yet logged in.
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            //if the token is valid
            if (jwtService.isTokenValid(jwt, userDetails)) {
                //Update the security context and send the request to the controller

                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken
                                (userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                //update security context holder
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
            filterChain.doFilter(request, response);
        }
        // UserDetails userDetails=this
    }
}
