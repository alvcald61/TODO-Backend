package com.portfolio.todolist.service.dto

import com.fasterxml.jackson.annotation.JsonProperty

data class LoginDto (
    val username: String? = null,
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    val jwt: String? = null,
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    val password: String?=null
) 