package com.example.azureb2c;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(properties = {
        "spring.security.oauth2.client.registration.azure.client-id=test-client-id",
        "spring.security.oauth2.client.registration.azure.client-secret=test-client-secret",
        "spring.security.oauth2.client.provider.azure.issuer-uri=https://test.example.com",
        "app.base-url=http://localhost:8080"
})
class AzureB2cApplicationTests {

    @MockBean
    private ClientRegistrationRepository clientRegistrationRepository;

    @Test
    void contextLoads() {
        // This test verifies that the Spring application context can load successfully
    }
}