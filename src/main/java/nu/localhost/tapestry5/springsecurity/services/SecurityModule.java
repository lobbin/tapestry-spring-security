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

package nu.localhost.tapestry.acegi.services;

import java.util.List;

import nu.localhost.tapestry.acegi.services.internal.AcegiExceptionTranslationFilter;
import nu.localhost.tapestry.acegi.services.internal.AcegiWorker;
import nu.localhost.tapestry.acegi.services.internal.HttpServletRequestFilterWrapper;
import nu.localhost.tapestry.acegi.services.internal.LogoutServiceImpl;
import nu.localhost.tapestry.acegi.services.internal.RequestFilterWrapper;
import nu.localhost.tapestry.acegi.services.internal.SaltSourceImpl;
import nu.localhost.tapestry.acegi.services.internal.SecurityChecker;
import nu.localhost.tapestry.acegi.services.internal.StaticSecurityChecker;

import org.acegisecurity.AccessDecisionManager;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.AuthenticationTrustResolver;
import org.acegisecurity.AuthenticationTrustResolverImpl;
import org.acegisecurity.context.HttpSessionContextIntegrationFilter;
import org.acegisecurity.context.SecurityContextImpl;
import org.acegisecurity.providers.AuthenticationProvider;
import org.acegisecurity.providers.ProviderManager;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationProvider;
import org.acegisecurity.providers.anonymous.AnonymousProcessingFilter;
import org.acegisecurity.providers.dao.DaoAuthenticationProvider;
import org.acegisecurity.providers.encoding.PasswordEncoder;
import org.acegisecurity.providers.rememberme.RememberMeAuthenticationProvider;
import org.acegisecurity.ui.AccessDeniedHandlerImpl;
import org.acegisecurity.ui.AuthenticationEntryPoint;
import org.acegisecurity.ui.ExceptionTranslationFilter;
import org.acegisecurity.ui.logout.LogoutHandler;
import org.acegisecurity.ui.logout.SecurityContextLogoutHandler;
import org.acegisecurity.ui.rememberme.RememberMeProcessingFilter;
import org.acegisecurity.ui.rememberme.RememberMeServices;
import org.acegisecurity.ui.rememberme.TokenBasedRememberMeServices;
import org.acegisecurity.ui.webapp.AuthenticationProcessingFilter;
import org.acegisecurity.ui.webapp.AuthenticationProcessingFilterEntryPoint;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.memory.UserAttribute;
import org.acegisecurity.userdetails.memory.UserAttributeEditor;
import org.acegisecurity.vote.AccessDecisionVoter;
import org.acegisecurity.vote.AffirmativeBased;
import org.acegisecurity.vote.RoleVoter;
import org.acegisecurity.wrapper.SecurityContextHolderAwareRequestFilter;
import org.apache.tapestry5.ioc.Configuration;
import org.apache.tapestry5.ioc.MappedConfiguration;
import org.apache.tapestry5.ioc.OrderedConfiguration;
import org.apache.tapestry5.ioc.ServiceBinder;
import org.apache.tapestry5.ioc.annotations.Inject;
import org.apache.tapestry5.ioc.annotations.InjectService;
import org.apache.tapestry5.ioc.annotations.Marker;
import org.apache.tapestry5.ioc.annotations.Value;
import org.apache.tapestry5.services.AliasContribution;
import org.apache.tapestry5.services.ComponentClassTransformWorker;
import org.apache.tapestry5.services.HttpServletRequestFilter;
import org.apache.tapestry5.services.LibraryMapping;
import org.apache.tapestry5.services.RequestFilter;
import org.apache.tapestry5.services.RequestGlobals;


/**
 * This module is automatically included as part of the Tapestry IoC Registry,
 * 
 * @author Ivan Dubrov
 * @author Robin Helgelin
 */
public class SecurityModule {
    @SuppressWarnings("unchecked")
    public static void bind(final ServiceBinder binder) {
        binder.bind(LogoutService.class, LogoutServiceImpl.class).withMarker(AcegiServices.class);
        binder.bind(AuthenticationTrustResolver.class, AuthenticationTrustResolverImpl.class)
            .withMarker(AcegiServices.class);
    }
    
    public static void contributeAlias(@AcegiServices SaltSourceService saltSource,
            @AcegiServices AuthenticationProcessingFilter authenticationProcessingFilter,
            Configuration<AliasContribution> configuration) {
        configuration.add(AliasContribution.create(SaltSourceService.class, saltSource));
        configuration.add(AliasContribution.create(AuthenticationProcessingFilter.class, authenticationProcessingFilter));
    }
    
    @Marker(AcegiServices.class)
    public static PasswordEncoder buildPasswordEncoder(
            @Inject @Value("${acegi.password.encoder}") final String passwordEncoder) {
        try {
            return (PasswordEncoder) Class.forName(passwordEncoder).newInstance();
        } catch (ClassNotFoundException ex) {
            throw new IllegalArgumentException(ex);
        } catch (IllegalAccessException ex) {
            throw new IllegalArgumentException(ex);
        } catch (InstantiationException ex) {
            throw new IllegalArgumentException(ex);
        }
    }
    
    @Marker(AcegiServices.class)
    public static SaltSourceService buildSaltSource(@Inject @Value("${acegi.password.salt}") final String salt)
        throws Exception {
        SaltSourceImpl saltSource = new SaltSourceImpl();
        saltSource.setSystemWideSalt(salt);
        saltSource.afterPropertiesSet();
        return saltSource;
    }
    
    public static void contributeFactoryDefaults(final MappedConfiguration<String, String> configuration) {
        configuration.add("acegi.check.url", "/j_acegi_security_check");
        configuration.add("acegi.failure.url", "/loginfailed");
        configuration.add("acegi.target.url", "/");
        configuration.add("acegi.afterlogout.url", "/");
        configuration.add("acegi.accessDenied.url", "");
        configuration.add("acegi.rememberme.key", "REMEMBERMEKEY");
        configuration.add("acegi.loginform.url", "/loginpage");
        configuration.add("acegi.anonymous.key", "acegi_anonymous");
        configuration.add("acegi.anonymous.attribute", "anonymous,ROLE_ANONYMOUS");
        configuration.add("acegi.password.encoder", "org.acegisecurity.providers.encoding.PlaintextPasswordEncoder");
        configuration.add("acegi.password.salt", "DEADBEEF");
    }
    
    public static void contributeComponentClassTransformWorker(
            OrderedConfiguration<ComponentClassTransformWorker> configuration, SecurityChecker securityChecker) {
        configuration.add("Acegi", new AcegiWorker(securityChecker));
    }
    
    public static void contributeHttpServletRequestHandler(
          OrderedConfiguration<HttpServletRequestFilter> configuration,
          @InjectService("HttpSessionContextIntegrationFilter") HttpServletRequestFilter httpSessionContextIntegrationFilter,
          @InjectService("AuthenticationProcessingFilter") HttpServletRequestFilter authenticationProcessingFilter,
          @InjectService("RememberMeProcessingFilter") HttpServletRequestFilter rememberMeProcessingFilter,
          @InjectService("SecurityContextHolderAwareRequestFilter") HttpServletRequestFilter
          securityContextHolderAwareRequestFilter,
          @InjectService("AnonymousProcessingFilter") HttpServletRequestFilter anonymousProcessingFilter) {

        configuration.add("acegiHttpSessionContextIntegrationFilter", httpSessionContextIntegrationFilter, "before:acegi*");
        configuration.add("acegiAuthenticationProcessingFilter", authenticationProcessingFilter);
        configuration.add("acegiRememberMeProcessingFilter", rememberMeProcessingFilter);
        configuration.add("acegiSecurityContextHolderAwareRequestFilter", securityContextHolderAwareRequestFilter,
                "after:acegiRememberMeProcessingFilter");
        configuration.add("acegiAnonymousProcessingFilter", anonymousProcessingFilter,
                "after:acegiRememberMeProcessingFilter",
                "after:acegiAuthenticationProcessingFilter");
    }

    @Marker(AcegiServices.class)
    public static HttpServletRequestFilter buildHttpSessionContextIntegrationFilter()
    throws Exception {
        HttpSessionContextIntegrationFilter filter = new HttpSessionContextIntegrationFilter();
        filter.setContext(SecurityContextImpl.class);
        filter.setAllowSessionCreation(true);
        filter.setForceEagerSessionCreation(false);
        filter.afterPropertiesSet();
        return new HttpServletRequestFilterWrapper(filter);
    }
    
    @Marker(AcegiServices.class)
    public static AuthenticationProcessingFilter buildRealAuthenticationProcessingFilter(
        @AcegiServices final AuthenticationManager manager,
        @AcegiServices final RememberMeServices rememberMeServices,
        @Inject @Value("${acegi.check.url}") final String authUrl,
        @Inject @Value("${acegi.target.url}") final String targetUrl,
        @Inject @Value("${acegi.failure.url}") final String failureUrl)
    throws Exception {
        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();
        filter.setAuthenticationManager(manager);
        filter.setAuthenticationFailureUrl(failureUrl);
        filter.setDefaultTargetUrl(targetUrl);
        filter.setFilterProcessesUrl(authUrl);
        filter.setRememberMeServices(rememberMeServices);
        filter.afterPropertiesSet();
        return filter;
    }    

    @Marker(AcegiServices.class)
    public static HttpServletRequestFilter buildAuthenticationProcessingFilter(final AuthenticationProcessingFilter filter)
    throws Exception {
        return new HttpServletRequestFilterWrapper(filter);
    }

    @Marker(AcegiServices.class)
    public static HttpServletRequestFilter buildRememberMeProcessingFilter(
            @AcegiServices final RememberMeServices rememberMe,
            @AcegiServices final AuthenticationManager authManager) throws Exception {
        RememberMeProcessingFilter filter = new RememberMeProcessingFilter();
        filter.setRememberMeServices(rememberMe);
        filter.setAuthenticationManager(authManager);
        filter.afterPropertiesSet();
        return new HttpServletRequestFilterWrapper(filter);
    }
    
    @Marker(AcegiServices.class)
    public static HttpServletRequestFilter buildSecurityContextHolderAwareRequestFilter() {
        return new HttpServletRequestFilterWrapper(new SecurityContextHolderAwareRequestFilter());
    }

    @Marker(AcegiServices.class)
    public static HttpServletRequestFilter buildAnonymousProcessingFilter(
            @Inject @Value("${acegi.anonymous.attribute}") final String anonymousAttr,
            @Inject @Value("${acegi.anonymous.key}") final String anonymousKey) throws Exception {
        AnonymousProcessingFilter filter = new AnonymousProcessingFilter();
        filter.setKey(anonymousKey);
        UserAttributeEditor attrEditor = new UserAttributeEditor();
        attrEditor.setAsText(anonymousAttr);
        UserAttribute attr = (UserAttribute) attrEditor.getValue();
        filter.setUserAttribute(attr);
        filter.afterPropertiesSet();
        return new HttpServletRequestFilterWrapper(filter);
    }

    @Marker(AcegiServices.class)
    public static RememberMeServices build(final UserDetailsService userDetailsService,
            @Inject @Value("${acegi.rememberme.key}") final String rememberMeKey) {
        TokenBasedRememberMeServices rememberMe = new TokenBasedRememberMeServices();
        rememberMe.setUserDetailsService(userDetailsService);
        rememberMe.setKey(rememberMeKey);
        return rememberMe;
    }

    @Marker(AcegiServices.class)
    public static LogoutHandler buildRememberMeLogoutHandler(final UserDetailsService userDetailsService,
            @Inject @Value("${acegi.rememberme.key}") final String rememberMeKey) throws Exception {
        TokenBasedRememberMeServices rememberMe = new TokenBasedRememberMeServices();
        rememberMe.setUserDetailsService(userDetailsService);
        rememberMe.setKey(rememberMeKey);
        rememberMe.afterPropertiesSet();
        return rememberMe;
    }

    public static void contributeLogoutService(final OrderedConfiguration< LogoutHandler > cfg,
            @InjectService("RememberMeLogoutHandler") final LogoutHandler rememberMeLogoutHandler) {
        cfg.add("securityContextLogoutHandler", new SecurityContextLogoutHandler());
        cfg.add("rememberMeLogoutHandler", rememberMeLogoutHandler);
    }

    @Marker(AcegiServices.class)
    public static AuthenticationManager buildProviderManager(final List< AuthenticationProvider > providers)
    throws Exception {
        ProviderManager manager = new ProviderManager();
        manager.setProviders(providers);
        manager.afterPropertiesSet();
        return manager;
    }

    @Marker(AcegiServices.class)
    public final AuthenticationProvider buildAnonymousAuthenticationProvider(
            @Inject @Value("${acegi.anonymous.key}") final String anonymousKey)
    throws Exception {
        AnonymousAuthenticationProvider provider = new AnonymousAuthenticationProvider();
        provider.setKey(anonymousKey);
        provider.afterPropertiesSet();
        return provider;
    }

    @Marker(AcegiServices.class)
    public final AuthenticationProvider buildRememberMeAuthenticationProvider(
            @Inject @Value("${acegi.rememberme.key}") final String rememberMeKey)
    throws Exception {
        RememberMeAuthenticationProvider provider = new RememberMeAuthenticationProvider();
        provider.setKey(rememberMeKey);
        provider.afterPropertiesSet();
        return provider;
    }

    @Marker(AcegiServices.class)
    public final AuthenticationProvider buildDaoAuthenticationProvider(final UserDetailsService userDetailsService,
            @AcegiServices final PasswordEncoder passwordEncoder,
            final SaltSourceService saltSource) throws Exception {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        provider.setSaltSource(saltSource);
        provider.afterPropertiesSet();
        return provider;
    }

    public final void contributeProviderManager(
            final OrderedConfiguration< AuthenticationProvider > configuration,
            @InjectService("AnonymousAuthenticationProvider")
            final AuthenticationProvider anonymousAuthenticationProvider,
            @InjectService("RememberMeAuthenticationProvider") 
            final AuthenticationProvider rememberMeAuthenticationProvider) {
        configuration.add("anonymousAuthenticationProvider", anonymousAuthenticationProvider);
        configuration.add("rememberMeAuthenticationProvider", rememberMeAuthenticationProvider);
    }

    @Marker(AcegiServices.class)
    public final AccessDecisionManager buildAccessDecisionManager(final List<AccessDecisionVoter> voters)
    throws Exception {
        AffirmativeBased manager = new AffirmativeBased();
        manager.setDecisionVoters(voters);
        manager.afterPropertiesSet();
        return manager;
    }

    public final void contributeAccessDecisionManager(final OrderedConfiguration< AccessDecisionVoter > configuration) {
        configuration.add("RoleVoter", new RoleVoter());
    }

    @Marker(AcegiServices.class)
    public static SecurityChecker buildSecurityChecker(
            @AcegiServices final AccessDecisionManager accessDecisionManager,
            @AcegiServices final AuthenticationManager authenticationManager)
    throws Exception {
        StaticSecurityChecker checker = new StaticSecurityChecker();
        checker.setAccessDecisionManager(accessDecisionManager);
        checker.setAuthenticationManager(authenticationManager);
        checker.afterPropertiesSet();
        return checker;
    }

    @Marker(AcegiServices.class)
    public static AuthenticationEntryPoint buildAuthenticationEntryPoint(
            @Inject @Value("${acegi.loginform.url}") final String loginFormUrl)
    throws Exception {
        AuthenticationProcessingFilterEntryPoint entryPoint = new AuthenticationProcessingFilterEntryPoint();
        entryPoint.setLoginFormUrl(loginFormUrl);
        entryPoint.afterPropertiesSet();
        return entryPoint;
    }

    @Marker(AcegiServices.class)
    public static RequestFilter buildAcegiExceptionFilter(final RequestGlobals globals, final AuthenticationEntryPoint aep,
            @Inject @Value("${acegi.accessDenied.url}") final String accessDeniedUrl)
    throws Exception {
        ExceptionTranslationFilter filter = new AcegiExceptionTranslationFilter();
        filter.setAuthenticationEntryPoint(aep);
        if (!accessDeniedUrl.equals("")) {
            AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
            accessDeniedHandler.setErrorPage(accessDeniedUrl);
            filter.setAccessDeniedHandler(accessDeniedHandler);
        }
        filter.afterPropertiesSet();
        return new RequestFilterWrapper(globals, filter);
    }

    public static void contributeRequestHandler(final OrderedConfiguration< RequestFilter > configuration,
            @InjectService("AcegiExceptionFilter") final RequestFilter acegiExceptionFilter) {
        configuration.add("AcegiExceptionFilter", acegiExceptionFilter, "after:ErrorFilter");
    }

    // Contribute three aspects of module: presentation, entities and
    // configuration
    public static void contributeComponentClassResolver(
            final Configuration< LibraryMapping > configuration) {
        configuration.add(new LibraryMapping("security", "nu.localhost.tapestry.acegi"));
    }
}
