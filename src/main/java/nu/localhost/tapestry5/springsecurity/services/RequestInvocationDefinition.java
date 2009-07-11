package nu.localhost.tapestry5.springsecurity.services;

import org.apache.commons.lang.StringUtils;

import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.intercept.web.RequestKey;

/**
 * Straight forward mapping definition of HttpRequestURIs to intercept by
 * FilterSecurityInterceptor.
 * 
 * @author Michael Gerzabek
 * 
 */
public class RequestInvocationDefinition {

    private RequestKey requestKey;
    private ConfigAttributeDefinition configAttributeDefinition;

    public RequestInvocationDefinition(String key, String roles) {
        this.requestKey = new RequestKey(key);
        this.configAttributeDefinition = new ConfigAttributeDefinition(
            StringUtils.stripAll(
                StringUtils.splitPreserveAllTokens(roles, ',')
            )
        );
    }

    public RequestKey getRequestKey() {
        return requestKey;
    }

    public void setRequestKey(RequestKey requestKey) {
        this.requestKey = requestKey;
    }

    public ConfigAttributeDefinition getConfigAttributeDefinition() {
        return configAttributeDefinition;
    }

    public void setConfigAttributeDefinition(
            ConfigAttributeDefinition configAttributeDefinition) {
        this.configAttributeDefinition = configAttributeDefinition;
    }

}
