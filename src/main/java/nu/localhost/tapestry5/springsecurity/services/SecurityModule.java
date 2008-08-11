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

package nu.localhost.tapestry5.springsecurity.services;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

import nu.localhost.tapestry5.springsecurity.services.internal.HttpServletRequestFilterWrapper;
import nu.localhost.tapestry5.springsecurity.services.internal.LogoutServiceImpl;
import nu.localhost.tapestry5.springsecurity.services.internal.RequestFilterWrapper;
import nu.localhost.tapestry5.springsecurity.services.internal.SaltSourceImpl;
import nu.localhost.tapestry5.springsecurity.services.internal.SecurityChecker;
import nu.localhost.tapestry5.springsecurity.services.internal.SpringSecurityExceptionTranslationFilter;
import nu.localhost.tapestry5.springsecurity.services.internal.SpringSecurityWorker;
import nu.localhost.tapestry5.springsecurity.services.internal.StaticSecurityChecker;
import nu.localhost.tapestry5.springsecurity.services.internal.T5AccessDeniedHandler;

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
import org.springframework.security.AccessDecisionManager;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.AuthenticationTrustResolver;
import org.springframework.security.AuthenticationTrustResolverImpl;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.context.HttpSessionContextIntegrationFilter;
import org.springframework.security.context.SecurityContextImpl;
import org.springframework.security.intercept.web.DefaultFilterInvocationDefinitionSource;
import org.springframework.security.intercept.web.FilterSecurityInterceptor;
import org.springframework.security.intercept.web.RequestKey;
import org.springframework.security.providers.AuthenticationProvider;
import org.springframework.security.providers.ProviderManager;
import org.springframework.security.providers.anonymous.AnonymousAuthenticationProvider;
import org.springframework.security.providers.anonymous.AnonymousProcessingFilter;
import org.springframework.security.providers.dao.DaoAuthenticationProvider;
import org.springframework.security.providers.encoding.PasswordEncoder;
import org.springframework.security.providers.encoding.PlaintextPasswordEncoder;
import org.springframework.security.providers.rememberme.RememberMeAuthenticationProvider;
import org.springframework.security.ui.AuthenticationEntryPoint;
import org.springframework.security.ui.logout.LogoutHandler;
import org.springframework.security.ui.logout.SecurityContextLogoutHandler;
import org.springframework.security.ui.rememberme.RememberMeProcessingFilter;
import org.springframework.security.ui.rememberme.RememberMeServices;
import org.springframework.security.ui.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.ui.webapp.AuthenticationProcessingFilter;
import org.springframework.security.ui.webapp.AuthenticationProcessingFilterEntryPoint;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.userdetails.memory.UserAttribute;
import org.springframework.security.userdetails.memory.UserAttributeEditor;
import org.springframework.security.util.AntUrlPathMatcher;
import org.springframework.security.vote.AccessDecisionVoter;
import org.springframework.security.vote.AffirmativeBased;
import org.springframework.security.vote.RoleVoter;
import org.springframework.security.wrapper.SecurityContextHolderAwareRequestFilter;

/**
 * This module is automatically included as part of the Tapestry IoC Registry,
 * 
 * @author Ivan Dubrov
 * @author Robin Helgelin
 * @author Michael Gerzabek
 */
public class SecurityModule {
    @SuppressWarnings("unchecked")
    public static void bind(final ServiceBinder binder) {
        binder.bind(LogoutService.class, LogoutServiceImpl.class).withMarker(
                SpringSecurityServices.class);
        binder.bind(AuthenticationTrustResolver.class,
                AuthenticationTrustResolverImpl.class).withMarker(
                SpringSecurityServices.class);
        binder.bind( PasswordEncoder.class, 
                PlaintextPasswordEncoder.class ).withMarker( 
                SpringSecurityServices.class);
    }

    public static void contributeAlias(
        @SpringSecurityServices
        SaltSourceService saltSource, 
        @SpringSecurityServices
        AuthenticationProcessingFilter authenticationProcessingFilter,
        Configuration<AliasContribution<?>> configuration) {
        
        configuration.add(AliasContribution.create(SaltSourceService.class,
                saltSource));
        configuration.add(AliasContribution.create(
                AuthenticationProcessingFilter.class,
                authenticationProcessingFilter));
    }

    @Marker(SpringSecurityServices.class)
    public static SaltSourceService buildSaltSource(@Inject
    @Value("${spring-security.password.salt}")
    final String salt) throws Exception {
        SaltSourceImpl saltSource = new SaltSourceImpl();
        saltSource.setSystemWideSalt(salt);
        saltSource.afterPropertiesSet();
        return saltSource;
    }

    public static void contributeFactoryDefaults(
            final MappedConfiguration<String, String> configuration) {
        configuration.add("spring-security.check.url",
                "/j_spring_security_check");
        configuration.add("spring-security.failure.url", "/loginfailed");
        configuration.add("spring-security.target.url", "/");
        configuration.add("spring-security.afterlogout.url", "/");
        configuration.add("spring-security.accessDenied.url", "");
        configuration.add("spring-security.force.ssl.login", "false");
        configuration.add("spring-security.rememberme.key", "REMEMBERMEKEY");
        configuration.add("spring-security.loginform.url", "/loginpage");
        configuration.add("spring-security.anonymous.key", "spring_anonymous");
        configuration.add("spring-security.anonymous.attribute",
                "anonymous,ROLE_ANONYMOUS");
        configuration.add("spring-security.password.salt", "DEADBEEF");
    }

    public static void contributeComponentClassTransformWorker(
            OrderedConfiguration<ComponentClassTransformWorker> configuration,
            SecurityChecker securityChecker) {
        configuration.add("SpringSecurity", new SpringSecurityWorker(
                securityChecker));
    }

    public static void contributeHttpServletRequestHandler(
            OrderedConfiguration<HttpServletRequestFilter> configuration,
            @InjectService("HttpSessionContextIntegrationFilter")
            HttpServletRequestFilter httpSessionContextIntegrationFilter,
            @InjectService("AuthenticationProcessingFilter")
            HttpServletRequestFilter authenticationProcessingFilter,
            @InjectService("RememberMeProcessingFilter")
            HttpServletRequestFilter rememberMeProcessingFilter,
            @InjectService("SecurityContextHolderAwareRequestFilter")
            HttpServletRequestFilter securityContextHolderAwareRequestFilter,
            @InjectService("AnonymousProcessingFilter")
            HttpServletRequestFilter anonymousProcessingFilter,
            @InjectService("FilterSecurityInterceptor")
            HttpServletRequestFilter filterSecurityInterceptor,
            @InjectService("SpringSecurityExceptionFilter")
            SpringSecurityExceptionTranslationFilter springSecurityExceptionFilter) {

        configuration.add("springSecurityHttpSessionContextIntegrationFilter",
                httpSessionContextIntegrationFilter, "before:springSecurity*");
        configuration.add("springSecurityAuthenticationProcessingFilter",
                authenticationProcessingFilter);
        configuration.add("springSecurityRememberMeProcessingFilter",
                rememberMeProcessingFilter);
        configuration.add(
                "springSecuritySecurityContextHolderAwareRequestFilter",
                securityContextHolderAwareRequestFilter,
                "after:springSecurityRememberMeProcessingFilter");
        configuration.add("springSecurityAnonymousProcessingFilter",
                anonymousProcessingFilter,
                "after:springSecurityRememberMeProcessingFilter",
                "after:springSecurityAuthenticationProcessingFilter");
        configuration.add("springSecurityExceptionFilter",
                new HttpServletRequestFilterWrapper(
                        springSecurityExceptionFilter),
                "before:springSecurityFilterSecurityInterceptor");
        configuration.add("springSecurityFilterSecurityInterceptor",
                filterSecurityInterceptor, "after:springSecurity*");
    }

    @Marker(SpringSecurityServices.class)
    public static HttpServletRequestFilter buildFilterSecurityInterceptor(
            @SpringSecurityServices
            final AccessDecisionManager accessDecisionManager,
            @SpringSecurityServices
            final AuthenticationManager manager,
            final Collection<RequestInvocationDefinition> contributions)
            throws Exception {

        FilterSecurityInterceptor interceptor = new FilterSecurityInterceptor();
        LinkedHashMap<RequestKey, ConfigAttributeDefinition> requestMap = convertCollectionToLinkedHashMap(contributions);
        DefaultFilterInvocationDefinitionSource source = new DefaultFilterInvocationDefinitionSource(
                new AntUrlPathMatcher(true), requestMap);
        interceptor.setAccessDecisionManager(accessDecisionManager);
        interceptor.setAlwaysReauthenticate(false);
        interceptor.setAuthenticationManager(manager);
        interceptor.setObjectDefinitionSource(source);
        interceptor.setValidateConfigAttributes(true);
        interceptor.afterPropertiesSet();
        return new HttpServletRequestFilterWrapper(interceptor);
    }

    static LinkedHashMap<RequestKey, ConfigAttributeDefinition> convertCollectionToLinkedHashMap(
            Collection<RequestInvocationDefinition> urls) {

        LinkedHashMap<RequestKey, ConfigAttributeDefinition> requestMap 
            = new LinkedHashMap<RequestKey, ConfigAttributeDefinition>();
        for (RequestInvocationDefinition url : urls) {

            requestMap.put(url.getRequestKey(), url
                    .getConfigAttributeDefinition());
        }
        return requestMap;
    }

    @Marker(SpringSecurityServices.class)
    public static HttpServletRequestFilter buildHttpSessionContextIntegrationFilter()
            throws Exception {
        HttpSessionContextIntegrationFilter filter = new HttpSessionContextIntegrationFilter();
        filter.setContextClass(SecurityContextImpl.class);
        filter.setAllowSessionCreation(true);
        filter.setForceEagerSessionCreation(false);
        filter.afterPropertiesSet();
        return new HttpServletRequestFilterWrapper(filter);
    }

    @Marker(SpringSecurityServices.class)
    public static AuthenticationProcessingFilter buildRealAuthenticationProcessingFilter(
            @SpringSecurityServices
            final AuthenticationManager manager, @SpringSecurityServices
            final RememberMeServices rememberMeServices, @Inject
            @Value("${spring-security.check.url}")
            final String authUrl, @Inject
            @Value("${spring-security.target.url}")
            final String targetUrl, @Inject
            @Value("${spring-security.failure.url}")
            final String failureUrl) throws Exception {
        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();
        filter.setAuthenticationManager(manager);
        filter.setAuthenticationFailureUrl(failureUrl);
        filter.setDefaultTargetUrl(targetUrl);
        filter.setFilterProcessesUrl(authUrl);
        filter.setRememberMeServices(rememberMeServices);
        filter.afterPropertiesSet();
        return filter;
    }

    @Marker(SpringSecurityServices.class)
    public static HttpServletRequestFilter buildAuthenticationProcessingFilter(
            final AuthenticationProcessingFilter filter) throws Exception {
        return new HttpServletRequestFilterWrapper(filter);
    }

    @Marker(SpringSecurityServices.class)
    public static HttpServletRequestFilter buildRememberMeProcessingFilter(
            @SpringSecurityServices
            final RememberMeServices rememberMe, @SpringSecurityServices
            final AuthenticationManager authManager) throws Exception {
        RememberMeProcessingFilter filter = new RememberMeProcessingFilter();
        filter.setRememberMeServices(rememberMe);
        filter.setAuthenticationManager(authManager);
        filter.afterPropertiesSet();
        return new HttpServletRequestFilterWrapper(filter);
    }

    @Marker(SpringSecurityServices.class)
    public static HttpServletRequestFilter buildSecurityContextHolderAwareRequestFilter() {
        return new HttpServletRequestFilterWrapper(
                new SecurityContextHolderAwareRequestFilter());
    }

    @Marker(SpringSecurityServices.class)
    public static HttpServletRequestFilter buildAnonymousProcessingFilter(
            @Inject
            @Value("${spring-security.anonymous.attribute}")
            final String anonymousAttr, @Inject
            @Value("${spring-security.anonymous.key}")
            final String anonymousKey) throws Exception {
        AnonymousProcessingFilter filter = new AnonymousProcessingFilter();
        filter.setKey(anonymousKey);
        UserAttributeEditor attrEditor = new UserAttributeEditor();
        attrEditor.setAsText(anonymousAttr);
        UserAttribute attr = (UserAttribute) attrEditor.getValue();
        filter.setUserAttribute(attr);
        filter.afterPropertiesSet();
        return new HttpServletRequestFilterWrapper(filter);
    }

    @Marker(SpringSecurityServices.class)
    public static RememberMeServices build(
            final UserDetailsService userDetailsService, @Inject
            @Value("${spring-security.rememberme.key}")
            final String rememberMeKey) {
        TokenBasedRememberMeServices rememberMe = new TokenBasedRememberMeServices();
        rememberMe.setUserDetailsService(userDetailsService);
        rememberMe.setKey(rememberMeKey);
        return rememberMe;
    }

    @Marker(SpringSecurityServices.class)
    public static LogoutHandler buildRememberMeLogoutHandler(
            final UserDetailsService userDetailsService, @Inject
            @Value("${spring-security.rememberme.key}")
            final String rememberMeKey) throws Exception {
        TokenBasedRememberMeServices rememberMe = new TokenBasedRememberMeServices();
        rememberMe.setUserDetailsService(userDetailsService);
        rememberMe.setKey(rememberMeKey);
        rememberMe.afterPropertiesSet();
        return rememberMe;
    }

    public static void contributeLogoutService(
            final OrderedConfiguration<LogoutHandler> cfg,
            @InjectService("RememberMeLogoutHandler")
            final LogoutHandler rememberMeLogoutHandler) {
        cfg.add("securityContextLogoutHandler",
                new SecurityContextLogoutHandler());
        cfg.add("rememberMeLogoutHandler", rememberMeLogoutHandler);
    }

    @Marker(SpringSecurityServices.class)
    public static AuthenticationManager buildProviderManager(
            final List<AuthenticationProvider> providers) throws Exception {
        ProviderManager manager = new ProviderManager();
        manager.setProviders(providers);
        manager.afterPropertiesSet();
        return manager;
    }

    @Marker(SpringSecurityServices.class)
    public final AuthenticationProvider buildAnonymousAuthenticationProvider(
            @Inject
            @Value("${spring-security.anonymous.key}")
            final String anonymousKey) throws Exception {
        AnonymousAuthenticationProvider provider = new AnonymousAuthenticationProvider();
        provider.setKey(anonymousKey);
        provider.afterPropertiesSet();
        return provider;
    }

    @Marker(SpringSecurityServices.class)
    public final AuthenticationProvider buildRememberMeAuthenticationProvider(
            @Inject
            @Value("${spring-security.rememberme.key}")
            final String rememberMeKey) throws Exception {
        RememberMeAuthenticationProvider provider = new RememberMeAuthenticationProvider();
        provider.setKey(rememberMeKey);
        provider.afterPropertiesSet();
        return provider;
    }

    @Marker(SpringSecurityServices.class)
    public final AuthenticationProvider buildDaoAuthenticationProvider(
            final UserDetailsService userDetailsService,
            final PasswordEncoder passwordEncoder,
            final SaltSourceService saltSource) throws Exception {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        provider.setSaltSource(saltSource);
        provider.afterPropertiesSet();
        return provider;
    }

    public final void contributeProviderManager(
            final OrderedConfiguration<AuthenticationProvider> configuration,
            @InjectService("AnonymousAuthenticationProvider")
            final AuthenticationProvider anonymousAuthenticationProvider,
            @InjectService("RememberMeAuthenticationProvider")
            final AuthenticationProvider rememberMeAuthenticationProvider) {
        configuration.add("anonymousAuthenticationProvider",
                anonymousAuthenticationProvider);
        configuration.add("rememberMeAuthenticationProvider",
                rememberMeAuthenticationProvider);
    }

    @Marker(SpringSecurityServices.class)
    public final AccessDecisionManager buildAccessDecisionManager(
            final List<AccessDecisionVoter> voters) throws Exception {
        AffirmativeBased manager = new AffirmativeBased();
        manager.setDecisionVoters(voters);
        manager.afterPropertiesSet();
        return manager;
    }

    public final void contributeAccessDecisionManager(
            final OrderedConfiguration<AccessDecisionVoter> configuration) {
        configuration.add("RoleVoter", new RoleVoter());
    }

    @Marker(SpringSecurityServices.class)
    public static SecurityChecker buildSecurityChecker(@SpringSecurityServices
    final AccessDecisionManager accessDecisionManager, @SpringSecurityServices
    final AuthenticationManager authenticationManager) throws Exception {
        StaticSecurityChecker checker = new StaticSecurityChecker();
        checker.setAccessDecisionManager(accessDecisionManager);
        checker.setAuthenticationManager(authenticationManager);
        checker.afterPropertiesSet();
        return checker;
    }

    @Marker(SpringSecurityServices.class)
    public static AuthenticationEntryPoint buildAuthenticationEntryPoint(
            @Inject
            @Value("${spring-security.loginform.url}")
            final String loginFormUrl, @Inject
            @Value("${spring-security.force.ssl.login}")
            final String forceHttps) throws Exception {

        AuthenticationProcessingFilterEntryPoint entryPoint = new AuthenticationProcessingFilterEntryPoint();
        entryPoint.setLoginFormUrl(loginFormUrl);
        entryPoint.afterPropertiesSet();
        boolean forceSSL = Boolean.parseBoolean(forceHttps);
        entryPoint.setForceHttps(forceSSL);
        return entryPoint;
    }

    public static SpringSecurityExceptionTranslationFilter buildSpringSecurityExceptionFilter(
            final AuthenticationEntryPoint aep, @Inject
            @Value("${spring-security.accessDenied.url}")
            final String accessDeniedUrl) throws Exception {

        SpringSecurityExceptionTranslationFilter filter = new SpringSecurityExceptionTranslationFilter();
        filter.setAuthenticationEntryPoint(aep);
        if (!accessDeniedUrl.equals("")) {
            T5AccessDeniedHandler accessDeniedHandler = new T5AccessDeniedHandler();
            accessDeniedHandler.setErrorPage(accessDeniedUrl);
            filter.setAccessDeniedHandler(accessDeniedHandler);
        }
        filter.afterPropertiesSet();
        return filter;
    }

    public static void contributeRequestHandler(
            final OrderedConfiguration<RequestFilter> configuration,
            final RequestGlobals globals,
            @InjectService("SpringSecurityExceptionFilter")
            final SpringSecurityExceptionTranslationFilter springSecurityExceptionFilter) {

        configuration
                .add("SpringSecurityExceptionFilter", new RequestFilterWrapper(
                        globals, springSecurityExceptionFilter),
                        "after:ErrorFilter");
    }

    // Contribute three aspects of module: presentation, entities and
    // configuration
    public static void contributeComponentClassResolver(
            final Configuration<LibraryMapping> configuration) {
        configuration.add(new LibraryMapping("security",
                "nu.localhost.tapestry5.springsecurity"));
    }

}
