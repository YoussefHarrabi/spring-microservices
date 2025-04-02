package com.example.users.Services.UserServices;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.util.Map;

@Service
public class EmailTemplateService {

    private final TemplateEngine templateEngine;

    @Autowired
    public EmailTemplateService(TemplateEngine templateEngine) {
        this.templateEngine = templateEngine;
    }

    public String processTemplate(String templateName, Map<String, Object> variables) {
        Context context = new Context();

        if (variables != null) {
            variables.forEach(context::setVariable);
        }

        return templateEngine.process(templateName, context);
    }
}