package com.vgt.apigateway.Config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vgt.apigateway.Model.BaseResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

public class JwtAuthenticationFilter implements WebFilter {

    @Autowired
    JwtService jwtService;

    private static final String AUTH_PATH = "/api/auth/";


    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        if (request.getURI().getPath().startsWith(AUTH_PATH)) { // skip jika /api/auth, entah kenapa permit all belum berfungsi
            return chain.filter(exchange);
        }

        // Ambil token dari header Authorization
        String token = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (token == null || !token.startsWith("Bearer ")) {
            return onError(exchange, "Missing or invalid token", HttpStatus.UNAUTHORIZED);
        }
        token = token.substring(7); // buang kata bearer
        try {
            // Validasi token
            if (!jwtService.isTokenValid(token)) {
                return onError(exchange, "Invalid or expired token", HttpStatus.UNAUTHORIZED);
            }
        } catch (Exception e) {
            return onError(exchange, "Token validation failed: " + e.getMessage(), HttpStatus.UNAUTHORIZED);
        }

        ServerHttpRequest modifiedRequest = exchange.getRequest()
                .mutate()
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build();

        exchange.getRequest().mutate().headers(httpHeaders -> {
            System.out.println("🛠️ Headers sebelum diteruskan ke service: " + httpHeaders);
        });

        return chain.filter(exchange.mutate().request(modifiedRequest).build());
    }

    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
        try {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(status);
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
            response.getHeaders().set(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*");

            BaseResponse errorResponse = BaseResponse.builder()
                    .status(status.value())
                    .message(message)
                    .build();

            // Konversi BaseResponse ke JSON
            byte[] responseBody = new ObjectMapper().writeValueAsBytes(errorResponse);

            return response.writeWith(Mono.just(response.bufferFactory().wrap(responseBody)));

        } catch (Exception e) {
            return exchange.getResponse().setComplete();
        }
    }
}
