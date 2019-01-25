package com.erikschouten.springjwtauthenticator

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.springframework.http.MediaType
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class APIAuthenticationFilter(loginUrl: String = "/login") : AbstractAuthenticationProcessingFilter(loginUrl) {

    init {
        setAuthenticationSuccessHandler { _, response, _ ->
            run {
                response.status = HttpServletResponse.SC_OK
                response.contentType = MediaType.APPLICATION_JSON_VALUE
                response.writer.write(ObjectMapper().writeValueAsString(
                        SecurityContextHolder.getContext().authentication.authorities.map { it.authority }))
            }
        }
        setAuthenticationFailureHandler { _, response, _ -> response.status = HttpServletResponse.SC_UNAUTHORIZED }
    }

    //Catch /login request, authenticate token generated from credentials extracted from the request
    override fun attemptAuthentication(request: HttpServletRequest, response: HttpServletResponse): Authentication {
        if (request.method != "POST") {
            throw AuthenticationServiceException("Authentication method not supported: " + request.method)
        }

        val credentials = jacksonObjectMapper().readValue(request.inputStream, AccountCredentials::class.java)
        if (credentials.email == null && credentials.username == null) throw Exception("Need username or email field")
        val authToken = UsernamePasswordAuthenticationToken(credentials.username ?: credentials.email, credentials.password)

        return authenticationManager.authenticate(authToken)
    }

    class AccountCredentials(val email: String?, val username: String?, val password: String)
}
