package com.portfolio.todolist.mapper

import ch.qos.logback.core.util.TimeUtil
import com.portfolio.todolist.model.Todo
import com.portfolio.todolist.model.User
import com.portfolio.todolist.service.dto.TodoDto
import com.portfolio.todolist.service.dto.UserDto
import org.modelmapper.ModelMapper
import org.springframework.context.annotation.Configuration
import org.springframework.stereotype.Component
import java.text.SimpleDateFormat
import java.time.LocalDate
import java.util.*

@Component
class Mapper(
    val modelMapper: ModelMapper
) {
    fun userToDto(user: User): UserDto {
        return UserDto(
            id = user.id,
            name = user.name,
            username = user.username,
            password = user.password,
            user.todos.map(this::todoToDto).toMutableList()
        )
    }
    
    fun dtoToUser(userDto: UserDto): User {
        val list = userDto.todos?.map(this::dtoToTodo)?.toMutableList()
        return User(
            userDto.id,
            userDto.name,
            userDto.username,
            userDto.password,
            list?: mutableListOf()
            )
    }
    
    fun dtoToTodo(todoDto: TodoDto): Todo {
        return Todo(
            todoDto.id,
            todoDto.title,
            todoDto.description,
            todoDto.isDone,
            SimpleDateFormat("dd/MM/yyyy HH:mm").parse(todoDto.creationDate),
        )
    }
    
    fun todoToDto(todo: Todo): TodoDto {
        return TodoDto(
            id = todo.id,
            title = todo.title,
            description = todo.description,
            isDone = todo.isDone,
            SimpleDateFormat("dd/MM/yyyy HH:mm").format(todo.creationDate),
        )
    }
}