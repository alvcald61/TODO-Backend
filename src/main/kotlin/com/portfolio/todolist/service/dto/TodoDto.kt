package com.portfolio.todolist.service.dto

import com.fasterxml.jackson.annotation.JsonProperty
import java.text.SimpleDateFormat
import java.util.*

data class TodoDto(
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    var id: String?,
    var title: String,
    var description: String,
    var isDone: Boolean = false,
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    var creationDate: String = SimpleDateFormat("dd/MM/yyyy HH:mm").format(Date())
)
