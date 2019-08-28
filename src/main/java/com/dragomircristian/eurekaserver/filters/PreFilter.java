package com.dragomircristian.eurekaserver.filters;

import com.dragomircristian.eurekaserver.handlers.RestTemplateErrorHandler;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.apache.http.ssl.SSLContexts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

public class PreFilter extends ZuulFilter {
    @Value("${url.oauthApiUrl}")
    String oauthApiUrl;

    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 1;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    @Override
    public Object run() throws ZuulException {
        RequestContext context = RequestContext.getCurrentContext();
        String authorization = context.getRequest().getHeader("Authorization") == null ? "" : context.getRequest().getHeader("Authorization");
        String notSent = "Authorization token was not sent.";
        String notValid = "Authorization token is not valid.";

        if (authorization.equals("")) {
            context.setResponseBody(notSent);
            context.setResponseStatusCode(HttpStatus.UNAUTHORIZED.value());
            context.setSendZuulResponse(false);
            return null;
        }

        TrustStrategy acceptingTrustStrategy = (cert, authType) -> true;
        SSLContext sslContext = null;
        try {
            sslContext = SSLContexts.custom().loadTrustMaterial(null, acceptingTrustStrategy).build();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext,
                NoopHostnameVerifier.INSTANCE);

        Registry<ConnectionSocketFactory> socketFactoryRegistry =
                RegistryBuilder.<ConnectionSocketFactory>create()
                        .register("https", sslsf)
                        .register("http", new PlainConnectionSocketFactory())
                        .build();

        BasicHttpClientConnectionManager connectionManager =
                new BasicHttpClientConnectionManager(socketFactoryRegistry);
        CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(sslsf)
                .setConnectionManager(connectionManager).build();
        String urlOverHttps = "https://localhost:8445/check-token";
        HttpComponentsClientHttpRequestFactory requestFactory =
                new HttpComponentsClientHttpRequestFactory(httpClient);
        RestTemplate restTemplate = new RestTemplate(requestFactory);
        restTemplate.setErrorHandler(new RestTemplateErrorHandler());

        HttpHeaders requestHeaders = new HttpHeaders();
        requestHeaders.add("Authorization", authorization);
        HttpEntity<String> requestEntity = new HttpEntity<>(requestHeaders);
        ResponseEntity<String> response = restTemplate
                .exchange(urlOverHttps, HttpMethod.GET, requestEntity, String.class);

        if (!(response.getStatusCode() == HttpStatus.OK)) {
            context.setResponseBody(notValid);
            context.setResponseStatusCode(HttpStatus.UNAUTHORIZED.value());
            context.setSendZuulResponse(false);
            return null;
        }

        return null;
    }
}
