package com.portfolio.todolist.model

import lombok.Data
import lombok.NoArgsConstructor
import org.springframework.data.annotation.Id
import org.springframework.data.mongodb.core.index.Indexed
import org.springframework.data.mongodb.core.mapping.Document

@Document(collection = "User")
@NoArgsConstructor
data class User(
    @Id
    var id: String? = null,
    var name: String? = null,
    @Indexed(unique = true)
    var username: String? = null,
    var password: String? = null,
    var todos: MutableList<Todo> = mutableListOf()
)
