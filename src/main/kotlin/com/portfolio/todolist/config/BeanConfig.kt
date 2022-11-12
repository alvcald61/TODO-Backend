package com.portfolio.todolist.config

import org.modelmapper.ModelMapper
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class BeanConfig {
    
    @Bean
    fun getModelMapper(): ModelMapper {
        return ModelMapper()
    }
}