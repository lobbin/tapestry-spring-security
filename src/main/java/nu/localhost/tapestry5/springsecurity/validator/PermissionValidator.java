package nu.localhost.tapestry5.springsecurity.validator;

import org.apache.tapestry5.Field;
import org.apache.tapestry5.MarkupWriter;
import org.apache.tapestry5.ValidationException;
import org.apache.tapestry5.ioc.MessageFormatter;
import org.apache.tapestry5.services.FormSupport;
import org.apache.tapestry5.validator.AbstractValidator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Permission validator with Spring security. It could detect if the HTTP POST is tempered manually in case the input
 * element was already removed from HTML by the component
 * {@link nu.localhost.tapestry5.springsecurity.components.IfLoggedIn} or
 * {@link nu.localhost.tapestry5.springsecurity.componentss.IfRole}.<br/>
 * <b>NOTE:</b> It only works for fields with parameter validate (for instance for
 * {@link org.apache.tapestry5.corelib.components.Checkbox} not).<br/>
 * <i>Usage:</i>
 * 
 * <pre>
 * &#064;Component(parameters = {&quot;value=dto.value&quot;, &quot;validate=permission=permission_value&quot;})
 * private TextField protectedField;
 * </pre>
 * 
 * The <code>permission_value</code> is either a single value or a semicolon separated list.
 * 
 * @author ferengra
 */
public class PermissionValidator extends AbstractValidator<String, Object> {

    public static final String NAME = "permission";
    public static final String MESSAGE = "validator-permission";

    /**
     * Constructor.
     */
    public PermissionValidator() {
        super(String.class, Object.class, MESSAGE);
    }

    public void validate(Field field, String constraintValue, MessageFormatter formatter, Object value)
        throws ValidationException {
        Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();
        if (null != currentUser) {
            for (GrantedAuthority authority : currentUser.getAuthorities()) {
                for (String permission : constraintValue.split(";")) {
                    if (authority.getAuthority().equals(permission)) {
                        return;
                    }
                }
            }
        }
        throw new ValidationException(buildMessage(formatter, field, constraintValue));
    }

    public void render(Field field, String constraintValue, MessageFormatter formatter, MarkupWriter writer,
        FormSupport formSupport) {
        formSupport.addValidation(field, NAME, buildMessage(formatter, field, constraintValue),
            constraintValue);
    }

    private String buildMessage(MessageFormatter formatter, Field field, String constraintValue) {
        return formatter.format(constraintValue, field.getLabel());
    }
}
