package com.portfolio.todolist.service.Impl

import com.portfolio.todolist.mapper.Mapper
import com.portfolio.todolist.model.User
import com.portfolio.todolist.repository.UserRepository
import com.portfolio.todolist.service.UserService
import com.portfolio.todolist.service.dto.LoginDto
import com.portfolio.todolist.service.dto.TodoDto
import com.portfolio.todolist.service.dto.UserDto
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Service
import java.nio.file.attribute.UserPrincipalNotFoundException
import java.util.UUID.randomUUID

@Service
class UserServiceImpl(
    val userRepository: UserRepository, 
    val mapper: Mapper
): UserService, UserDetailsService {
    override fun getUser(username: String): UserDto {
        val user = userRepository.findByUsername(username) ?: throw ClassNotFoundException("User not found")
        return mapper.userToDto(user)
    }

    override fun listAll(): List<UserDto> {
        val users = userRepository.findAll()
        return users.map(mapper::userToDto)
    }

    override fun save(userDto: UserDto): UserDto {
        validateUserExistence(userDto.username!!)
        var user : User = mapper.dtoToUser(userDto)
        user.password  = BCryptPasswordEncoder().encode(user.password)
        user = userRepository.save(user)
        return mapper.userToDto(user)
    }
    
    fun validateUserExistence(username: String) {
        if (userRepository.findByUsername(username) != null){
            throw IllegalArgumentException("User already exists")
        }
    }

    override fun delete(id: String): Boolean {
        userRepository.deleteById(id)
        return true
    }

    override fun addTodo(username: String, todo: TodoDto) : UserDto {
        val user = userRepository.findByUsername(username) ?: throw ClassNotFoundException("User not found")
        todo.id = randomUUID().toString()
        user.todos.add(mapper.dtoToTodo(todo))
        return mapper.userToDto(userRepository.save(user)) 
    }

    override fun removeTodo(username: String, todoId: String) {
        val user = userRepository.findByUsername(username) ?: throw ClassNotFoundException("User not found")
        user.todos.removeIf { todo -> todo.id == todoId }
        userRepository.save(user)
    }
    override fun completeTodo(username: String, todoId: String) {
        val user = userRepository.findByUsername(username) ?: throw ClassNotFoundException("User not found")
        val todo = user.todos.find { todo -> todo.id == todoId }
        todo?.isDone = true
        userRepository.save(user)
    }

    override fun getTodos(username: String): List<TodoDto> {
        val user = userRepository.findByUsername(username) ?: throw ClassNotFoundException("User not found")
        return user.todos.map(mapper::todoToDto)
    }

    override fun login(username: String, password: String?): LoginDto {
        val user = userRepository.findByUsername(username) ?: throw ClassNotFoundException("User not found")
        if(user.password != password) {
            throw UserPrincipalNotFoundException("Wrong password");
        }
        return LoginDto(user.username!!, user.id, user.password)
    }

    override fun loadUserByUsername(username: String): UserDetails {
        val user = userRepository.findByUsername(username) ?: throw ClassNotFoundException("User not found")
        return org.springframework.security.core.userdetails.User(user.username, user.password, emptyList())
    }

}