package com.portfolio.todolist.model

import org.springframework.data.annotation.Id
import org.springframework.data.mongodb.core.mapping.Document
import java.util.*

@Document(collection = "todo")
data class Todo(
    @Id
    var id: String?,
    var title: String,
    var description: String,
    var isDone: Boolean,
    var creationDate: Date,
)
