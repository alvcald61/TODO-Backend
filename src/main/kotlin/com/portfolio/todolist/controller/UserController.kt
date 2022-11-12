package com.portfolio.todolist.controller

import com.portfolio.todolist.TodoListApplication
import com.portfolio.todolist.service.UserService
import com.portfolio.todolist.service.dto.LoginDto
import com.portfolio.todolist.service.dto.TodoDto
import com.portfolio.todolist.service.dto.UserDto
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.CrossOrigin
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/users")
@CrossOrigin
class UserController(
    val userService: UserService
) {

    @GetMapping
    @ResponseStatus(HttpStatus.OK)
    fun getAllUsers() = userService.listAll()

    @GetMapping("/{username}")
    @ResponseStatus(HttpStatus.FOUND)
    fun getUserByUsername(@PathVariable username: String) = userService.getUser(username)

    @GetMapping("/{username}/todos")
    @ResponseStatus(HttpStatus.OK)
    fun getTodosByUserByUsername(@PathVariable username: String) = userService.getTodos(username)

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    fun createUser(@RequestBody userDto: UserDto) = userService.save(userDto)
    
    @DeleteMapping("/{username}")
    @ResponseStatus(HttpStatus.OK)    
    fun deleteUser(@PathVariable username: String) = userService.delete(username)
    
    @PostMapping("/addTodo/{username}")
    @ResponseStatus(HttpStatus.CREATED)
    fun addTodoToUser(@PathVariable username: String, @RequestBody todo: TodoDto) = userService.addTodo(username, todo)

    @DeleteMapping("/deleteTodo/{username}/{todoId}")
    @ResponseStatus(HttpStatus.OK)
    fun deleteTodoFromUser(@PathVariable username: String, @PathVariable todoId: String) = userService.removeTodo(username, todoId)

    @PutMapping("/completeTodo/{username}/{todoId}")
    @ResponseStatus(HttpStatus.OK)
    fun completeTodoFromUser(@PathVariable username: String, @PathVariable todoId: String) = userService.completeTodo(username, todoId)

//    @PostMapping("/login")
//    @ResponseStatus(HttpStatus.ACCEPTED)
//    fun login(@RequestBody userDto: LoginDto) = userService.login(userDto.username, userDto.password)
}