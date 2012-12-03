package nu.localhost.tapestry5.springsecurity.pages;

import org.apache.tapestry5.annotations.Component;
import org.apache.tapestry5.annotations.Property;
import org.apache.tapestry5.corelib.components.Form;
import org.apache.tapestry5.corelib.components.LinkSubmit;
import org.apache.tapestry5.corelib.components.TextField;

/**
 * Used for testing the PermissionValidator.
 * 
 * @author ferengra
 */
public class PermissionValidatorTestPage {

    @Property
    private String value;

    @Property
    private String protectedValue;

    @Component
    private Form form;

    @Component(parameters = {"value=value"})
    private TextField field;

    @Component(parameters = {"value=protectedValue", "validate=permission=permissionValue"})
    private TextField protectedField;

    @Component(parameters = {"value=protectedValue", "validate=permission=permissionValue;permissionValue2"})
    private TextField protectedListField;

    @Component
    private LinkSubmit submit;
}
