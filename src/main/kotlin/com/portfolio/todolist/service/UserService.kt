package com.portfolio.todolist.service

import com.portfolio.todolist.service.dto.LoginDto
import com.portfolio.todolist.service.dto.TodoDto
import com.portfolio.todolist.service.dto.UserDto

interface UserService {
    fun getUser(username: String): UserDto
    fun listAll(): List<UserDto>
    fun save(userDto: UserDto): UserDto
    fun delete(id: String): Boolean
    fun addTodo(username: String, todo: TodoDto): UserDto
    fun removeTodo(username: String, todoId: String)
    fun completeTodo(username: String, todoId: String)
    fun getTodos(username: String): List<TodoDto> 
    fun login(username: String, password: String?): LoginDto
}