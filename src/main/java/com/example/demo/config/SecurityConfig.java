package com.example.demo.config;

import com.example.demo.config.jwt.JwtAuthenticationFilter;
import com.example.demo.config.jwt.JwtAuthorizationFilter;
import com.example.demo.config.jwt.JwtProcessor;
import com.example.demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserRepository userRepository;
    private final JwtProcessor jwtProcessor;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager(), jwtProcessor);
        jwtAuthenticationFilter.setFilterProcessesUrl("/account/login"); // login url 주소 account/login으로 수정
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)// 세션 사용 X
                .and()
                .formLogin().disable()
                .httpBasic().disable()

                .addFilter(corsFilter())
                .addFilter(jwtAuthenticationFilter)
                .addFilter(new JwtAuthenticationFilter(authenticationManager(), jwtProcessor))
                .addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository, jwtProcessor))

                .authorizeRequests()
                .mvcMatchers("/account/register", "/account/login").permitAll() // login, register을 permitAll 해서 아무나 들어갈 수 있음
                /**
                 *  권한 설정
                 */
                .mvcMatchers("/account/api/user") // USER 권한이 있으면 들어갈 수 있음
                .access("hasAuthority('USER')")
                .anyRequest().hasAuthority("USER");
    }
    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true); // 서버가 json을 자바스크립트에서 처리할 수 있게 설정
        config.addAllowedOriginPattern("*"); // 모든 ip 응답 허용
        config.addAllowedHeader("*"); // 모든 header 응답 허용
        config.addAllowedMethod("*"); // 모든 post, delete, put, get 등의 요청 허용
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}