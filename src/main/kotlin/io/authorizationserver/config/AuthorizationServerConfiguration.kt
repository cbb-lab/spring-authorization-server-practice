package io.authorizationserver.config


import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import java.time.Duration
import java.util.UUID

@Configuration
class AuthorizationServerConfiguration {

    @Bean
    fun filterChain(
        http: HttpSecurity,
        registeredClientRepository: RegisteredClientRepository,
        authorizationService: OAuth2AuthorizationService,
        jwtEncoder: JwtEncoder,
        settings: AuthorizationServerSettings,
    ): SecurityFilterChain {
        OAuth2AuthorizationServerConfigurer()
            .apply {
                http.with(this) {
                    it.registeredClientRepository(registeredClientRepository)
                        .authorizationService(authorizationService)
                        .tokenGenerator(JwtGenerator(jwtEncoder))
                        .authorizationServerSettings(settings)
                }
            }

        http.csrf { it.disable() }
            .authorizeHttpRequests {
                it.requestMatchers(*ALLOWED_STATIC_RESOURCES).permitAll()
                    .anyRequest().authenticated()
            }
            .formLogin { formLogin ->
                formLogin.loginPage("/login").permitAll()
            }
            .logout { logout ->
                logout.logoutSuccessUrl("/login")
                logout.clearAuthentication(true)
                logout.deleteCookies("JSESSIONID")
            }
            .oauth2ResourceServer { it.jwt { } }
            .httpBasic { httpBasic -> httpBasic.disable() }

        return http.build()
    }

    @Bean
    fun authorizationService(): OAuth2AuthorizationService =
        InMemoryOAuth2AuthorizationService()

    @Bean
    fun registeredClientRepository(): RegisteredClientRepository {
        val registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientName("my-client")
            .clientId("clientId")
            .clientSecret("{noop}secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .clientSettings(ClientSettings.builder().build())
            .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(2)).build())
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .build()
        return InMemoryRegisteredClientRepository(registeredClient)
    }

    @Bean
    fun userDetailService(): UserDetailsService {
        val userDetails: UserDetails = User.withDefaultPasswordEncoder()
            .username("user")
            .password("pass")
            .roles("ADMIN", "USER")
            .build()
        return InMemoryUserDetailsManager(userDetails)
    }

    private companion object {
        private val ALLOWED_STATIC_RESOURCES = arrayOf(
            AntPathRequestMatcher("/assets/**"),
            AntPathRequestMatcher("/h2-console/**"),
        )
    }

}