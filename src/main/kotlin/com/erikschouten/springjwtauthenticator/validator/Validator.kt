package com.erikschouten.springjwtauthenticator.validator

import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetails

open class Validator {
    @Throws(ValidationException::class)
    open fun validate(userDetails: UserDetails) {}

    @Throws(ValidationException::class)
    open fun validate(authentication: Authentication) {}
}
