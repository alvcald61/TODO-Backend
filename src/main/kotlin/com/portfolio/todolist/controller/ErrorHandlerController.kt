package com.portfolio.todolist.controller

import io.jsonwebtoken.JwtException
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.util.MultiValueMap
import org.springframework.util.MultiValueMapAdapter
import org.springframework.validation.BindException
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.CrossOrigin
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.context.request.WebRequest
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler
import java.nio.file.attribute.UserPrincipalNotFoundException


@ControllerAdvice
@CrossOrigin(origins = ["*"])
class ErrorHandlerController : ResponseEntityExceptionHandler() {
    
    @ExceptionHandler(value = [ClassNotFoundException::class])
    protected fun handleConflict(ex: RuntimeException?, request: WebRequest?): ResponseEntity<Any> {
    return ResponseEntity(errorBody(ex?.message!!), HttpStatus.NOT_FOUND)
    }
    
    @ExceptionHandler(value = [IllegalArgumentException::class])
    protected fun handleIllegalArgument(ex: RuntimeException?, request: WebRequest?): ResponseEntity<Any> {
        return ResponseEntity(errorBody(ex?.message!!), HttpStatus.BAD_REQUEST)
    }
    
    @ExceptionHandler(value = [UserPrincipalNotFoundException::class, JwtException::class])
    protected fun handleUserPrincipalNotFoundException(ex: RuntimeException?, request: WebRequest?): ResponseEntity<Any> {
        return ResponseEntity(errorBody(ex?.message!!), HttpStatus.UNAUTHORIZED)
    }
//    @ExceptionHandler(value = [MethodArgumentNotValidException::class])
    override fun handleMethodArgumentNotValid(ex: MethodArgumentNotValidException, headers: HttpHeaders, status: HttpStatus, request: WebRequest): ResponseEntity<Any> {
        val exceptionErrors = (ex as BindException)
            .bindingResult
            .fieldErrors
            .map { x -> x.defaultMessage }
        return ResponseEntity(errorBody(exceptionErrors), HttpHeaders(), HttpStatus.BAD_REQUEST)
    }

    private fun errorBody(error: String): Map<String, Any>? {
        val body: MutableMap<String, Any> = LinkedHashMap()
        val errors: MutableList<String> = ArrayList()
        errors.add(error)
        body["errors"] = errors
        return body
    }

    private fun errorBody(exceptionErrors: List<String?>): Map<String, Any>? {
        val body: MutableMap<String, Any> = LinkedHashMap()
        body["errors"] = exceptionErrors
        return body
    }
}