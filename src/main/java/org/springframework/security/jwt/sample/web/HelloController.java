package org.springframework.security.jwt.sample.web;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.web.bind.annotation.RequestMethod.GET;

@RestController
@RequestMapping("/api/hello")
public class HelloController {

    @RequestMapping(method = GET, produces = APPLICATION_JSON_VALUE)
    public ResponseEntity hello(@RequestParam(value = "name", required = false) String name) {
        String message = String.format("Hello %s!", (name != null) ? name : "World");
        HelloResource resource = new HelloResource(message);
        return ResponseEntity.ok().body(resource);
    }}
