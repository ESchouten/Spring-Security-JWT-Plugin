package com.erikschouten.springjwtauthenticator.validator

import org.springframework.security.core.AuthenticationException

class ValidationException(message: String): AuthenticationException(message)
