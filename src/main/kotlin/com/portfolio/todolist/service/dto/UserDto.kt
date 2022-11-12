package com.portfolio.todolist.service.dto

import com.fasterxml.jackson.annotation.JsonProperty

data class UserDto (
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    val id: String? = null, 
    val name: String? = null, 
    val username: String? = null, 
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    val password: String? = null,
    val todos: MutableList<TodoDto>? = mutableListOf()
    )
        