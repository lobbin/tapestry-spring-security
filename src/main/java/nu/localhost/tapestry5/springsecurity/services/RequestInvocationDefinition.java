package nu.localhost.tapestry5.springsecurity.services;

import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.intercept.web.RequestKey;

/**
 * Straight forward mapping definition of HttpRequestURIs to intercept
 * by FilterSecurityInterceptor.
 * 
 * @author Michael Gerzabek
 *
 */
public class RequestInvocationDefinition {

	private RequestKey _requestKey;
	private ConfigAttributeDefinition _configAttributeDefinition;

	public RequestInvocationDefinition( String key, String roles ) {
	
		_requestKey = new RequestKey( key );
		_configAttributeDefinition = new ConfigAttributeDefinition( roles );
	}
	
	public RequestKey getRequestKey() {
		return _requestKey;
	}

	public void setRequestKey(RequestKey requestKey) {
		_requestKey = requestKey;
	}

	public ConfigAttributeDefinition getConfigAttributeDefinition() {
		return _configAttributeDefinition;
	}

	public void setConfigAttributeDefinition(
			ConfigAttributeDefinition configAttributeDefinition ) {
		_configAttributeDefinition = configAttributeDefinition;
	}

}
