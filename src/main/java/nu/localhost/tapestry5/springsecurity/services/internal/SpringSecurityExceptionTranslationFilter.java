/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.AccessDeniedException;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationTrustResolver;
import org.springframework.security.AuthenticationTrustResolverImpl;
import org.springframework.security.InsufficientAuthenticationException;
import org.springframework.security.SpringSecurityException;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.ui.AbstractProcessingFilter;
import org.springframework.security.ui.AccessDeniedHandler;
import org.springframework.security.ui.AccessDeniedHandlerImpl;
import org.springframework.security.ui.AuthenticationEntryPoint;
import org.springframework.security.ui.ExceptionTranslationFilter;
import org.springframework.security.ui.FilterChainOrder;
import org.springframework.security.ui.SpringSecurityFilter;
import org.springframework.security.ui.savedrequest.SavedRequest;
import org.springframework.security.util.PortResolver;
import org.springframework.security.util.PortResolverImpl;
import org.springframework.security.util.ThrowableAnalyzer;
import org.springframework.security.util.ThrowableCauseExtractor;
import org.springframework.util.Assert;

/**
 * @author Ben Alex
 * @author Colin Sampaleanu
 * @author Robin Helgelin
 * @author Michael Gerzabek
 */
/*
 * Since we need this filter also in the chain of the HttpServletRequestFilters
 * I copied the ExceptionTranslationFilter from Spring and adapted it to fullfill 
 * both our T5 HttpServletRequestFilterWrapper and RequestFilterWrapper signatures.
 */
public class SpringSecurityExceptionTranslationFilter extends
        SpringSecurityFilter {

    // ~ Instance fields
    // ================================================================================================

    private AccessDeniedHandler         accessDeniedHandler         = new AccessDeniedHandlerImpl();
    private AuthenticationEntryPoint    authenticationEntryPoint;
    private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();
    private PortResolver                portResolver                = new PortResolverImpl();
    private ThrowableAnalyzer           throwableAnalyzer           = new DefaultThrowableAnalyzer();
    private boolean                     createSessionAllowed        = true;

    // ~ Methods
    // ========================================================================================================

    public void afterPropertiesSet() throws Exception {

        Assert.notNull( authenticationEntryPoint,
                "authenticationEntryPoint must be specified" );
        Assert.notNull( portResolver, "portResolver must be specified" );
        Assert.notNull( authenticationTrustResolver,
                "authenticationTrustResolver must be specified" );
        Assert.notNull( throwableAnalyzer,
                "throwableAnalyzer must be specified" );
    }

    private static final Log logger = LogFactory
                                            .getLog( ExceptionTranslationFilter.class );

    public void doFilterHttp(
                              HttpServletRequest request,
                              HttpServletResponse response,
                              FilterChain chain )
        throws IOException,
        ServletException {

        try {
            chain.doFilter( request, response );

            if ( logger.isDebugEnabled() ) {
                logger.debug( "Chain processed normally" );
            }
        }
        catch ( IOException ex ) {
            throw ex;
        }
        catch ( Exception ex ) {
            // Try to extract a SpringSecurityException from the stacktrace
            Throwable[] causeChain = this.throwableAnalyzer
                    .determineCauseChain( ex );
            SpringSecurityException ase = (SpringSecurityException) this.throwableAnalyzer
                    .getFirstThrowableOfType( SpringSecurityException.class,
                            causeChain );

            if ( ase != null ) {
                handleException( request, response, chain, ase );
            }
            else {
                // Rethrow ServletExceptions and RuntimeExceptions as-is
                if ( ex instanceof ServletException ) {
                    throw (ServletException) ex;
                }
                else if ( ex instanceof RuntimeException ) { throw (RuntimeException) ex; }

                // Wrap other Exceptions. These are not expected to happen
                throw new RuntimeException( ex );
            }
        }
    }

    public void doFilterHttp(
                              final ServletRequest request,
                              final ServletResponse response,
                              final FilterChain chain )
        throws IOException,
        ServletException {

        if ( !( request instanceof HttpServletRequest ) ) { throw new ServletException(
                "HttpServletRequest required" ); }

        if ( !( response instanceof HttpServletResponse ) ) { throw new ServletException(
                "HttpServletResponse required" ); }

        doFilterHttp( (HttpServletRequest) request, (ServletResponse) response,
                chain );
    }

    public AuthenticationEntryPoint getAuthenticationEntryPoint() {

        return authenticationEntryPoint;
    }

    public AuthenticationTrustResolver getAuthenticationTrustResolver() {

        return authenticationTrustResolver;
    }

    public PortResolver getPortResolver() {

        return portResolver;
    }

    private void handleException(
                                  ServletRequest request,
                                  ServletResponse response,
                                  FilterChain chain,
                                  SpringSecurityException exception )
        throws IOException,
        ServletException {

        if ( exception instanceof AuthenticationException ) {
            if ( logger.isDebugEnabled() ) {
                logger
                        .debug(
                                "Authentication exception occurred; redirecting to authentication entry point",
                                exception );
            }

            sendStartAuthentication( request, response, chain,
                    (AuthenticationException) exception );
        }
        else if ( exception instanceof AccessDeniedException ) {
            if ( authenticationTrustResolver.isAnonymous( SecurityContextHolder
                    .getContext().getAuthentication() ) ) {
                if ( logger.isDebugEnabled() ) {
                    logger
                            .debug(
                                    "Access is denied (user is anonymous); redirecting to authentication entry point",
                                    exception );
                }

                sendStartAuthentication(
                        request,
                        response,
                        chain,
                        new InsufficientAuthenticationException(
                                "Full authentication is required to access this resource" ) );
            }
            else {
                if ( logger.isDebugEnabled() ) {
                    logger
                            .debug(
                                    "Access is denied (user is not anonymous); delegating to AccessDeniedHandler",
                                    exception );
                }

                accessDeniedHandler.handle( request, response,
                        (AccessDeniedException) exception );
            }
        }
    }

    /**
     * If <code>true</code>, indicates that
     * <code>SecurityEnforcementFilter</code> is permitted to store the target
     * URL and exception information in the <code>HttpSession</code> (the
     * default). In situations where you do not wish to unnecessarily create
     * <code>HttpSession</code>s - because the user agent will know the
     * failed URL, such as with BASIC or Digest authentication - you may wish to
     * set this property to <code>false</code>. Remember to also set the
     * {@link org.springframework.security.context.HttpSessionContextIntegrationFilter#allowSessionCreation}
     * to <code>false</code> if you set this property to <code>false</code>.
     * 
     * @return <code>true</code> if the <code>HttpSession</code> will be
     *         used to store information about the failed request,
     *         <code>false</code> if the <code>HttpSession</code> will not
     *         be used
     */
    public boolean isCreateSessionAllowed() {

        return createSessionAllowed;
    }

    protected void sendStartAuthentication(
                                            ServletRequest request,
                                            ServletResponse response,
                                            FilterChain chain,
                                            AuthenticationException reason )
        throws ServletException,
        IOException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        SavedRequest savedRequest = new SavedRequest( httpRequest, portResolver );

        if ( logger.isDebugEnabled() ) {
            logger
                    .debug( "Authentication entry point being called; SavedRequest added to Session: "
                            + savedRequest );
        }

        if ( createSessionAllowed ) {
            // Store the HTTP request itself. Used by AbstractProcessingFilter
            // for redirection after successful authentication (SEC-29)
            httpRequest.getSession().setAttribute(
                    AbstractProcessingFilter.SPRING_SECURITY_SAVED_REQUEST_KEY,
                    savedRequest );
        }

        // SEC-112: Clear the SecurityContextHolder's Authentication, as the
        // existing Authentication is no longer considered valid
        SecurityContextHolder.getContext().setAuthentication( null );

        authenticationEntryPoint.commence( httpRequest, response, reason );
    }

    public void setAccessDeniedHandler( AccessDeniedHandler accessDeniedHandler ) {

        Assert.notNull( accessDeniedHandler, "AccessDeniedHandler required" );
        this.accessDeniedHandler = accessDeniedHandler;
    }

    public void setAuthenticationEntryPoint(
                                             AuthenticationEntryPoint authenticationEntryPoint ) {

        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    public void setAuthenticationTrustResolver(
                                                AuthenticationTrustResolver authenticationTrustResolver ) {

        this.authenticationTrustResolver = authenticationTrustResolver;
    }

    public void setCreateSessionAllowed( boolean createSessionAllowed ) {

        this.createSessionAllowed = createSessionAllowed;
    }

    public void setPortResolver( PortResolver portResolver ) {

        this.portResolver = portResolver;
    }

    public void setThrowableAnalyzer( ThrowableAnalyzer throwableAnalyzer ) {

        this.throwableAnalyzer = throwableAnalyzer;
    }

    public int getOrder() {

        return FilterChainOrder.EXCEPTION_TRANSLATION_FILTER;
    }

    /**
     * Default implementation of <code>ThrowableAnalyzer</code> which is
     * capable of also unwrapping <code>ServletException</code>s.
     */
    private static final class DefaultThrowableAnalyzer extends
            ThrowableAnalyzer {

        /**
         * @see org.springframework.security.util.ThrowableAnalyzer#initExtractorMap()
         */
        protected void initExtractorMap() {

            super.initExtractorMap();

            registerExtractor( ServletException.class,
                    new ThrowableCauseExtractor() {

                        public Throwable extractCause( Throwable throwable ) {

                            ThrowableAnalyzer.verifyThrowableHierarchy(
                                    throwable, ServletException.class );
                            return ( (ServletException) throwable )
                                    .getRootCause();
                        }
                    } );
        }

    }
}
