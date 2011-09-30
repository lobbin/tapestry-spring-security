/*
 * Copyright 2007 Ivan Dubrov
 * Copyright 2007, 2008 Robin Helgelin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nu.localhost.tapestry5.springsecurity.services.internal;

import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

import org.apache.tapestry5.annotations.BeginRender;
import org.apache.tapestry5.annotations.CleanupRender;
import org.apache.tapestry5.model.MutableComponentModel;
import org.apache.tapestry5.services.ClassTransformation;
import org.apache.tapestry5.services.ComponentClassTransformWorker;
import org.apache.tapestry5.services.ComponentMethodAdvice;
import org.apache.tapestry5.services.ComponentMethodInvocation;
import org.apache.tapestry5.services.FieldAccess;
import org.apache.tapestry5.services.TransformConstants;
import org.apache.tapestry5.services.TransformField;
import org.apache.tapestry5.services.TransformMethod;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.intercept.InterceptorStatusToken;

/**
 * @author Ivan Dubrov
 */
public class SpringSecurityWorker implements ComponentClassTransformWorker {

    private SecurityChecker securityChecker;

    public SpringSecurityWorker(final SecurityChecker securityChecker) {

        this.securityChecker = securityChecker;
    }

    public final void transform(final ClassTransformation transformation, final MutableComponentModel model) {

        model.addRenderPhase(BeginRender.class);
        model.addRenderPhase(CleanupRender.class);

        // Secure methods
        for (TransformMethod method : transformation.matchMethodsWithAnnotation(Secured.class)) {
            transformMethod(transformation, method);
        }

        // Secure pages
        Secured annotation = transformation.getAnnotation(Secured.class);
        if (annotation != null) {

            transformPage(transformation, annotation);
        }
    }

    private void transformPage(final ClassTransformation transformation, final Secured annotation) {

        // Security checker

        final String interField = transformation.addInjectedField(SecurityChecker.class, "_$checker", securityChecker);        

        // Attribute definition
//        final String configField = createConfigAttributeDefinitionField(transformation, annotation);
        final ConfigAttributeHolder confAttrHolder = createConfigAttributeDefinitionField(transformation, annotation);
        
        // Interceptor token
//        final String tokenField = transformation.addField(
//                Modifier.PRIVATE,
//                org.springframework.security.access.intercept.InterceptorStatusToken.class.getName(),
//                "_$token" );

        TransformField tokenFieldInstance = transformation.createField(Modifier.PRIVATE,
                org.springframework.security.access.intercept.InterceptorStatusToken.class.getName(),
                "_$token"); // InterceptorStatusToken

        final FieldAccess tokenFieldAccess = tokenFieldInstance.getAccess();


        // Extend class
        TransformMethod beginRenderMethod = transformation.getOrCreateMethod(TransformConstants.BEGIN_RENDER_SIGNATURE);


        /** REPLACED by the block immediately below **/
//                transformation.extendMethod( TransformConstants.BEGIN_RENDER_SIGNATURE, tokenField + " = " + interField
//                + ".checkBefore(" + configField + ");" );
//
        final SecurityChecker secChecker = this.securityChecker;
        ComponentMethodAdvice beginRenderAdvice = new ComponentMethodAdvice() {

            public void advise(ComponentMethodInvocation invocation) {
                invocation.proceed();

                // tokenField + " = " + interField   + ".checkBefore(" + configField + ");"
//                ConfigAttributeHolder confAttrHolder = (ConfigAttributeHolder) configFieldInstance.read(invocation.getInstance());
                InterceptorStatusToken statusTokenVal = secChecker.checkBefore(confAttrHolder);
                tokenFieldAccess.write(invocation.getInstance(), statusTokenVal);
            }
        };

        beginRenderMethod.addAdvice(beginRenderAdvice);

        // ---------------- END TRANSFORMATION ------------------------


        TransformMethod cleanupRenderMethod = transformation.getOrCreateMethod(TransformConstants.CLEANUP_RENDER_SIGNATURE);

//        transformation.extendMethod( TransformConstants.CLEANUP_RENDER_SIGNATURE, interField + ".checkAfter("
//                + tokenField + ", null);" );
        ComponentMethodAdvice cleanupRenderAdvice = new ComponentMethodAdvice() {

            public void advise(ComponentMethodInvocation invocation) {
                invocation.proceed();

                // interField + ".checkAfter(" + tokenField + ", null);
                InterceptorStatusToken tokenFieldValue = (InterceptorStatusToken) tokenFieldAccess.read(invocation.getInstance());
                secChecker.checkAfter(tokenFieldValue, null);
            }
        };

        cleanupRenderMethod.addAdvice(cleanupRenderAdvice);

        // ------------- END TRANSFORMATION ------------------------

    }

    private void transformMethod(final ClassTransformation transformation, final TransformMethod method) {

        // Security checker
        final String interField = transformation.addInjectedField(SecurityChecker.class, "_$checker", securityChecker);

        TransformMethod securedMethod = transformation.getOrCreateMethod(method.getSignature());

        // Interceptor status token
//        final String statusToken = transformation.addField(
//                Modifier.PRIVATE,
//                org.springframework.security.access.intercept.InterceptorStatusToken.class.getName(),
//                "_$token");
        TransformField tokenFieldInstance = transformation.createField(Modifier.PRIVATE,
                org.springframework.security.access.intercept.InterceptorStatusToken.class.getName(),
                "_$token"); // InterceptorStatusToken

        final FieldAccess tokenFieldAccess = tokenFieldInstance.getAccess();

        // Attribute definition
        final Secured annotation = method.getAnnotation(Secured.class);
        //final String configField = createConfigAttributeDefinitionField(transformation, annotation);
        final ConfigAttributeHolder confAttrHolder = createConfigAttributeDefinitionField(transformation, annotation);

        // Prefix and extend method
//        transformation.prefixMethod(method, statusToken + " = " + interField + ".checkBefore(" + configField + ");");
//        transformation.extendExistingMethod(method, interField + ".checkAfter(" + statusToken + ", null);");
        final SecurityChecker secChecker = this.securityChecker;
        ComponentMethodAdvice securedMethodAdvice = new ComponentMethodAdvice() {

            public void advise(ComponentMethodInvocation invocation) {
                InterceptorStatusToken statusTokenVal = secChecker.checkBefore(confAttrHolder);
                tokenFieldAccess.write(invocation.getInstance(), statusTokenVal);
                
                invocation.proceed();

                // interField + ".checkAfter(" + tokenField + ", null);
                InterceptorStatusToken tokenFieldValue = (InterceptorStatusToken) tokenFieldAccess.read(invocation.getInstance());
                secChecker.checkAfter(tokenFieldValue, null);
            }
        };

        securedMethod.addAdvice(securedMethodAdvice);
    }

    private ConfigAttributeHolder createConfigAttributeDefinitionField(
            final ClassTransformation transformation,
            final Secured annotation) {

        List<ConfigAttribute> configAttributeDefinition = new ArrayList<ConfigAttribute>();
        for (String annValue : annotation.value()) {
            configAttributeDefinition.add(new SecurityConfig(annValue));
        }
        ConfigAttributeHolder configAttributeHolder = new ConfigAttributeHolder(configAttributeDefinition);
        transformation.addInjectedField(
                ConfigAttributeHolder.class,
                "_$configAttributeDefinition",
                configAttributeHolder);
        return configAttributeHolder;
    }
}
