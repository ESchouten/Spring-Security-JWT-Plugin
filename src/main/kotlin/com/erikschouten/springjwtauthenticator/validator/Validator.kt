package com.erikschouten.springjwtauthenticator.validator

import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Service

@Service
open class Validator {
    @Throws(ValidationException::class)
    open fun validate(userDetails: UserDetails) {}
}
