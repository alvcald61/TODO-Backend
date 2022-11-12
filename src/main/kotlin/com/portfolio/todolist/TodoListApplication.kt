package com.portfolio.todolist

import com.portfolio.todolist.model.User
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity

@SpringBootApplication
@EnableMongoRepositories
class TodoListApplication

fun main(args: Array<String>) {
    runApplication<TodoListApplication>(*args)
    val user = User()
}
