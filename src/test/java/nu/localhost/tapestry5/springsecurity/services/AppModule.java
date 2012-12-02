package nu.localhost.tapestry5.springsecurity.services;

import java.io.IOException;

import nu.localhost.tapestry5.springsecurity.validator.PermissionValidator;

import org.apache.tapestry5.SymbolConstants;
import org.apache.tapestry5.Validator;
import org.apache.tapestry5.ioc.Configuration;
import org.apache.tapestry5.ioc.MappedConfiguration;
import org.apache.tapestry5.ioc.OrderedConfiguration;
import org.apache.tapestry5.ioc.annotations.Contribute;
import org.apache.tapestry5.services.FieldValidatorSource;
import org.apache.tapestry5.services.LibraryMapping;
import org.apache.tapestry5.services.Request;
import org.apache.tapestry5.services.RequestFilter;
import org.apache.tapestry5.services.RequestGlobals;
import org.apache.tapestry5.services.RequestHandler;
import org.apache.tapestry5.services.Response;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Module for setting Tapestry environment for tests.
 * 
 * @author ferengra
 */
public class AppModule {

    public static void contributeApplicationDefaults(MappedConfiguration<String, String> configuration) {
        configuration.add(SymbolConstants.SUPPORTED_LOCALES, "en");
        configuration.add(SymbolConstants.PRODUCTION_MODE, "false");
    }

    public static void contributeComponentClassResolver(final Configuration<LibraryMapping> configuration) {
        configuration.add(new LibraryMapping(SecurityModule.MODULE_NAME, "nu.localhost.tapestry5.springsecurity"));
    }

    public static void contributeRequestHandler(final OrderedConfiguration<RequestFilter> config,
        final RequestGlobals requestGlobals) {
        RequestFilter filter = new RequestFilter() {
            public boolean service(Request request, Response response, RequestHandler handler) throws IOException {
                requestGlobals.storeServletRequestResponse(new MockHttpServletRequest(), new MockHttpServletResponse());
                return handler.service(request, response);
            }
        };
        config.add("EnsureNonNullHttpRequestAndResponse", filter, "before:*");
    }

    @Contribute(FieldValidatorSource.class)
    public static void addValidators(MappedConfiguration<String, Validator> configuration)
    {
        configuration.add(PermissionValidator.NAME, new PermissionValidator());
    }
}
