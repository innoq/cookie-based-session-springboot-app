package com.innoq.cookiebasedsessionapp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class LoginWithTargetUrlAuthenticationEntryPointTest {

    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;

    private LoginWithTargetUrlAuthenticationEntryPoint entryPoint = new LoginWithTargetUrlAuthenticationEntryPoint();

    @Test
    public void appends_targetURL() {
        when(request.getRequestURI()).thenReturn("/original/url");

        String url = entryPoint.determineUrlToUseForThisRequest(request, response, null);

        assertThat(url).isEqualTo("/login?target=/original/url");
    }

}
