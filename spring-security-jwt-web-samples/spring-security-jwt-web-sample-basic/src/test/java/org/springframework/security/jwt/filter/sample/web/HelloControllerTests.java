package org.springframework.security.jwt.filter.sample.web;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.security.jwt.filter.sample.Application;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.Filter;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = Application.class)
@WebAppConfiguration
public class HelloControllerTests {

    @Autowired
    private Filter springSecurityFilterChain;

    @Autowired
    private WebApplicationContext webApplicationContext;

    private MockMvc mockMvc;

    @Before
    public void setUpMockMvc() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(webApplicationContext)
                .addFilters(springSecurityFilterChain)
                .alwaysDo(print())
                .build();
    }

    /*
     * Login
     */

    @Test
    public void login_should_return_unauthorized_when_authentication_credentials_not_provided() throws Exception {
        mockMvc.perform(post("/login"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void login_should_return_unauthorized_when_invalid_password_provided() throws Exception {
        mockMvc.perform(post("/login")
                .header("X-Auth-Username", "user")
                .header("X-Auth-Password", "invalid_password"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void login_should_return_jwt_when_valid_credentials_provided() throws Exception {
        MvcResult result = mockMvc.perform(post("/login")
                .header("X-Auth-Username", "user")
                .header("X-Auth-Password", "pwd"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Auth-Token", is(notNullValue())))
                .andReturn();
        // TODO assert result
        String token = result.getResponse().getHeader("X-Auth-Token");
        System.out.println("token=" + token);
    }

    /*
     * Hello
     */

    @Test
    public void hello_should_return_unauthorized_when_jwt_not_provided() throws Exception {
        mockMvc.perform(get("/api/hello"))
                .andExpect(status().isUnauthorized());
    }
}
