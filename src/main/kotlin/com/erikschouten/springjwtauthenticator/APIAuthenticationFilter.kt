package com.erikschouten.springjwtauthenticator

import com.erikschouten.springjwtauthenticator.validator.Validator
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class APIAuthenticationFilter(loginUrl: String = "/login", private val validator: Validator = Validator()) : AbstractAuthenticationProcessingFilter(loginUrl) {

    init {
        setAuthenticationSuccessHandler { _, response, _ -> response.status = HttpServletResponse.SC_OK }
        setAuthenticationFailureHandler { _, response, _ -> response.status = HttpServletResponse.SC_UNAUTHORIZED }
    }

    //Catch /login request, authenticate token generated from credentials extracted from the request
    override fun attemptAuthentication(request: HttpServletRequest, response: HttpServletResponse): Authentication {
        if (request.method != "POST") {
            throw AuthenticationServiceException("Authentication method not supported: " + request.method)
        }

        val credentials = jacksonObjectMapper().readValue(request.inputStream, AccountCredentials::class.java)
        if (credentials.email == null && credentials.username == null) throw Exception("Need username or email field")
        val authToken = UsernamePasswordAuthenticationToken(credentials.username
                ?: credentials.email, credentials.password)

        val authentication = authenticationManager.authenticate(authToken)

        validator.validate(authentication)

        return authentication
    }

    class AccountCredentials(val email: String?, val username: String?, val password: String)
}
