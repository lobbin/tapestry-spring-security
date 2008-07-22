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

package nu.localhost.tapestry.acegi.services.internal;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.AcegiSecurityException;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.InsufficientAuthenticationException;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.ui.AccessDeniedHandler;
import org.acegisecurity.ui.AccessDeniedHandlerImpl;
import org.acegisecurity.ui.ExceptionTranslationFilter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.tapestry5.ioc.internal.util.TapestryException;
import org.springframework.util.Assert;

/**
 * @author Ben Alex
 * @author Colin Sampaleanu
 * @author Robin Helgelin
 */
public class AcegiExceptionTranslationFilter
extends ExceptionTranslationFilter {
    private static final Log logger = 
        LogFactory.getLog(ExceptionTranslationFilter.class);
    
    private AccessDeniedHandler accessDeniedHandler =
        new AccessDeniedHandlerImpl();
    
    public void doFilter(final ServletRequest request,
            final ServletResponse response,
            final FilterChain chain) throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest)) {
            throw new ServletException("HttpServletRequest required");
        }
        
        if (!(response instanceof HttpServletResponse)) {
            throw new ServletException("HttpServletResponse required");
        }
        
        try {
            chain.doFilter(request, response);
            
            if (logger.isDebugEnabled()) {
                logger.debug("Chain processed normally");
            }
        } catch (AuthenticationException ex) {
            handleException(request, response, chain, ex);
        } catch (AccessDeniedException ex) {
            handleException(request, response, chain, ex);
        } catch (TapestryException ex) {
            Throwable cause = getRootCause(ex);
            if (cause instanceof AuthenticationException || cause instanceof AccessDeniedException) {
                handleException(request, response, chain, (AcegiSecurityException) cause);
            } else {
                throw ex;
            }
        } catch (ServletException ex) {
            Throwable cause = ex.getRootCause();
            if (cause instanceof AuthenticationException || cause instanceof AccessDeniedException) {
                handleException(request, response, chain, (AcegiSecurityException) cause);
            } else {
                throw ex;
            }
        } catch (IOException ex) {
            throw ex;
        }
    }
    
    private Throwable getRootCause(Throwable t) {
        if (t.getCause() == null) {
            return t;
        }
        return getRootCause(t.getCause());
    }
    
    private void handleException(final ServletRequest request,
            final ServletResponse response,
            final FilterChain chain, final AcegiSecurityException exception)
    throws IOException, ServletException {
        if (exception instanceof AuthenticationException) {
            if (logger.isDebugEnabled()) {
                logger.debug("Authentication exception occurred; redirecting to authentication entry point", exception);
            }
            
            sendStartAuthentication(request, response, chain, 
                    (AuthenticationException) exception);
        } else if (exception instanceof AccessDeniedException) {
            if (getAuthenticationTrustResolver().isAnonymous(
                    SecurityContextHolder.getContext().getAuthentication())) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Access is denied (user is anonymous); redirecting to authentication entry point",
                            exception);
                }
                
                sendStartAuthentication(request, response, chain,
                        new InsufficientAuthenticationException("Full authentication is required to access this resource"));
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug("Access is denied (user is not anonymous); delegating to AccessDeniedHandler",
                            exception);
                }
                
                this.accessDeniedHandler.handle(request, response,
                        (AccessDeniedException) exception);
            }
        }
    }
    
    public void setAccessDeniedHandler(
            final AccessDeniedHandler accessDeniedHandler) {
        Assert.notNull(accessDeniedHandler, "AccessDeniedHandler required");
        this.accessDeniedHandler = accessDeniedHandler;
    }
}
