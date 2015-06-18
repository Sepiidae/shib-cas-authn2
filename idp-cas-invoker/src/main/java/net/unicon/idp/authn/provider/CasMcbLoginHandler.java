package net.unicon.idp.authn.provider;

import edu.internet2.middleware.assurance.mcb.authn.provider.MCBLoginServlet;
import edu.internet2.middleware.assurance.mcb.authn.provider.MCBSubmodule;
import edu.internet2.middleware.assurance.mcb.authn.provider.MCBUsernamePrincipal;
import edu.internet2.middleware.assurance.mcb.authn.provider.RemoteUserSubmodule;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationEngine;
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.lang.reflect.Constructor;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import net.unicon.idp.authn.provider.extra.EntityIdParameterBuilder;
import net.unicon.idp.authn.provider.extra.IParameterBuilder;
import net.unicon.idp.externalauth.CasCallbackServlet;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.internet2.middleware.shibboleth.idp.authn.LoginContext;
import edu.internet2.middleware.shibboleth.idp.authn.LoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.provider.AbstractLoginHandler;
import edu.internet2.middleware.shibboleth.idp.authn.provider.ExternalAuthnSystemLoginHandler;
import edu.internet2.middleware.shibboleth.idp.util.HttpServletHelper;
import java.util.logging.Level;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletException;
import net.unicon.idp.externalauth.AuthenticatedNameTranslator;
import net.unicon.idp.externalauth.CasToShibTranslator;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.jasig.cas.client.validation.TicketValidationException;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.util.DatatypeHelper;

/**
 * CasLoginHandler replaces the {@link CasInvokerServlet} AND
 * {@link CasAuthenticatorResource} (facade) from the v1.x implementations.
 * Allows simplification of the SHIB-CAS authenticator by removing the need to
 * configure and deploy a separate war.
 *
 * This LoginHandler handles taking the login request from Shib and translating
 * and sending the request on to the CAS instance.
 *
 * @author chasegawa@unicon.net
 */
public class CasMcbLoginHandler extends AbstractLoginHandler implements MCBSubmodule {

    private final Logger log = LoggerFactory.getLogger(CasMcbLoginHandler.class);

    private static final String MISSING_CONFIG_MSG = "Unable to create CasLoginHandler - missing {} property. Please check {}";
    private static final String LOGIN = "/login";
    private static final Logger LOGGER = LoggerFactory.getLogger(CasMcbLoginHandler.class);
    private String callbackUrl;
    private String casLoginUrl;
    private String casProtocol = "https";
    private String casPrefix = "/cas";
    private String casServer;
    private String idpProtocol = "https";
    private String idpServer;
    private String idpPrefix = "/idp";
    private String idpCallback = "/Authn/MCB/RemoteUser";
    private String propertiesFile = DEFAULT_CAS_SHIB_PROPS;
    private Set<IParameterBuilder> parameterBuilders = new HashSet<IParameterBuilder>();
    private Properties props;

    public static final String AUTHN_TYPE = "authnType";
    private static final String DEFAULT_CAS_SHIB_PROPS = "/opt/shibboleth-idp/conf/cas-shib.properties";
    private static final long serialVersionUID = 1L;
    private String artifactParameterName = "ticket";

    private String casToShibTranslatorNames;
    private String serverName;
    private Cas20ServiceTicketValidator ticketValidator;
    private Set<CasToShibTranslator> translators = new HashSet<CasToShibTranslator>();

    {
        // By default, we start with the entity id param builder included
        parameterBuilders.add(new EntityIdParameterBuilder());
    }

    public CasMcbLoginHandler() {

    }

    /**
     * @param paramBuilderNames The comma separated list of class names to
     * create.
     */
    private void createParamBuilders(final String paramBuilderNames) {
        for (String className : StringUtils.split(paramBuilderNames, ',')) {
            try {
                Class<?> c = Class.forName(className);
                Constructor<?> cons = c.getConstructor();
                parameterBuilders.add((IParameterBuilder) cons.newInstance());
            } catch (Exception e) {
                LOGGER.warn("Unable to create IParameterBuilder with classname {}", className, e);
            }
        }
    }

    /**
     * @param request The original servlet request
     * @return
     */
    private String getAdditionalParameters(final HttpServletRequest request) {
        StringBuilder builder = new StringBuilder();
        for (IParameterBuilder paramBuilder : parameterBuilders) {
            builder.append(paramBuilder.getParameterString(request));
        }
        return builder.toString();
    }

    /**
     * @return the property value or empty string if the key/value isn't found
     */
    private String getProperty(final String key) {
        String result = props.getProperty(key);
        return StringUtils.isEmpty(result) ? "" : result;
    }

    /**
     * Translate the SHIB request so that cas renew and/or gateway are set
     * properly before handing off to CAS.
     *
     * @see
     * edu.internet2.middleware.shibboleth.idp.authn.LoginHandler#login(javax.servlet.http.HttpServletRequest,
     * javax.servlet.http.HttpServletResponse)
     */
    @Override
    public void login(final HttpServletRequest request, final HttpServletResponse response) {
        ServletContext application = request.getSession().getServletContext();
        LoginContext loginContext = (LoginContext) HttpServletHelper.getLoginContext(
                HttpServletHelper.getStorageService(application), application, request);
        Boolean force = loginContext.isForceAuthRequired();

        // CAS Protocol - http://www.jasig.org/cas/protocol recommends that when this param is set, to set "true"
        String authnType = force ? "renew=true" : "";

        Boolean passive = loginContext.isPassiveAuthRequired();
        // CAS Protocol - http://www.jasig.org/cas/protocol indicates not setting gateway if renew has been set.
        // we will set both and let CAS sort it out, but log a warning 
        if (passive) {
            if (Boolean.TRUE.equals(force)) {
                authnType += "&";
                LOGGER.warn("Both FORCE AUTHN and PASSIVE AUTHN were set to true, please verify that the requesting system has been properly configured.");
            }
            authnType += "gateway=true";
        }
        try {
            HttpSession session = request.getSession();
            // Coupled this attribute to the CasCallbackServlet as that is the type that needs this bit of information
            session.setAttribute(CasCallbackServlet.AUTHN_TYPE, authnType);
            // Create the raw login string - Service/Callback URL should always be last
            StringBuilder loginString = new StringBuilder(casLoginUrl + "?");
            loginString.append(authnType);
            String additionalParams = getAdditionalParameters(request);
            if (StringUtils.endsWith(loginString.toString(), "?")) {
                additionalParams = StringUtils.removeStart(additionalParams, "&");
            }
            loginString.append(additionalParams);
            loginString.append(StringUtils.endsWith(loginString.toString(), "?") ? "service=" : "&service=");
            loginString.append(callbackUrl);
            LOGGER.error(loginString.toString());
            response.sendRedirect(response.encodeRedirectURL(loginString.toString()));
        } catch (final IOException e) {
            LOGGER.error("Unable to redirect to CAS from LoginHandler", e);
        }
    }

    @Override
    public boolean displayLogin(MCBLoginServlet servlet, HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, LoginException {
        login(request, response);
        return true;

    }

    @Override
    public boolean processLogin(MCBLoginServlet servlet, HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, LoginException {

        String ticket = CommonUtils.safeGetParameter(request, artifactParameterName);
        Object authnType = request.getSession().getAttribute(AUTHN_TYPE);
        Assertion assertion = null;
        try {
            ticketValidator.setRenew(null != authnType && authnType.toString().contains("&renew=true"));
            assertion = ticketValidator.validate(ticket, constructServiceUrl(request, response));

        } catch (final TicketValidationException e) {
            LOGGER.error("Unable to validate login attempt.", e);
            boolean wasPassiveAttempt = null != authnType && authnType.toString().contains("&gateway=true");
            // If it was a passive attempt, send back the indicator that the responding provider cannot authenticate 
            // the principal passively, as has been requested. Otherwise, send the generic authn failed code.
            request.setAttribute(LoginHandler.AUTHENTICATION_ERROR_KEY, wasPassiveAttempt ? StatusCode.NO_PASSIVE_URI
                    : StatusCode.AUTHN_FAILED_URI);
            // AuthenticationEngine.returnToAuthenticationEngine(request, response);

            return false;
        }

        // Convert the CAS principal to a MCB principal
        MCBUsernamePrincipal principal = (MCBUsernamePrincipal) request.getSession().getAttribute(LoginHandler.PRINCIPAL_KEY);
        try {
            String principalName = DatatypeHelper.safeTrimOrNullString(assertion.getPrincipal().getName());
            if (principalName != null) {
                log.debug("Remote user identified as {} returning control back to authentication engine", principalName);

                principal.setName(principalName);

                request.setAttribute(LoginHandler.PRINCIPAL_KEY, principal);

                return true;
            } else {
                log.debug("No remote user identified by protected servlet.");
                return false;
            }
        } catch (Exception e) {
            principal.setFailedLogin(e.getMessage());
            return false;
        }

        // AuthenticationEngine.returnToAuthenticationEngine(request, response);        

    }

    @Override
    public void init() {
        try {
            parseProperties();
        } catch (ServletException ex) {
            java.util.logging.Logger.getLogger(CasMcbLoginHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        buildTranslators();
    }

    private String beanName;

    @Override
    public String getBeanName() {
        return beanName;
    }

    @Override
    public void setBeanName(String beanName) {
        this.beanName = beanName;
    }

    /**
     * Attempt to build the set of translators from the fully qualified class
     * names set in the properties. If nothing has been set then default to the
     * AuthenticatedNameTranslator only.
     */
    private void buildTranslators() {
        translators.add(new AuthenticatedNameTranslator());
        for (String classname : StringUtils.split(casToShibTranslatorNames, ';')) {
            try {
                Class<?> c = Class.forName(classname);
                Constructor<?> cons = c.getConstructor();
                CasToShibTranslator casToShibTranslator = (CasToShibTranslator) cons.newInstance();
                translators.add(casToShibTranslator);
            } catch (Exception e) {
                LOGGER.error("Error building cas to shib translator with name: " + classname, e);
            }
        }
    }

    /**
     * Use the CAS CommonUtils to build the CAS Service URL.
     */
    private String constructServiceUrl(final HttpServletRequest request, final HttpServletResponse response) {
        return CommonUtils.constructServiceUrl(request, response, null, serverName, artifactParameterName, true);
    }

    /**
     * Check for the externalized properties first. If this hasn't been set, go
     * with the default filename/path If we are unable to load the parameters,
     * we will attempt to load from the init-params. Missing parameters will
     * cause an error - we will not attempt to mix initialization between props
     * and init-params.
     *
     * @throws ServletException
     */
    private void parseProperties() throws ServletException {
        FileReader reader = null;
        try {
            String casUrlPrefix = null;
            String artifactParamaterName = null;
            String fileName = this.propertiesFile;
            if (null == fileName || "".equals(fileName.trim())) {
                LOGGER.debug("propertiesFile init-param not set, defaulting to " + DEFAULT_CAS_SHIB_PROPS);
                fileName = DEFAULT_CAS_SHIB_PROPS;
            }
            props = new Properties();
            reader = new FileReader(new File(fileName));
            props.load(reader);
            reader.close();
            LOGGER.debug("Attempting to load parameters from properties file");
            String temp = getProperty("cas.server.protocol");
            casProtocol = StringUtils.isEmpty(temp) ? casProtocol : temp;
            temp = getProperty("cas.application.prefix");
            casPrefix = StringUtils.isEmpty(temp) ? casPrefix : temp;
            temp = getProperty("cas.server");
            casServer = StringUtils.isEmpty(temp) ? casServer : temp;
            temp = getProperty("idp.server.protocol");
            idpProtocol = StringUtils.isEmpty(temp) ? idpProtocol : temp;
            temp = getProperty("idp.server");
            idpServer = StringUtils.isEmpty(temp) ? idpServer : temp;
            artifactParamaterName = getProperty("artifact.parameter.name");
            casToShibTranslatorNames = getProperty("casToShibTranslators");

            casLoginUrl = casProtocol + "://" + casServer + casPrefix + LOGIN;

            temp = getProperty("idp.application.prefix");
            idpPrefix = StringUtils.isEmpty(temp) ? idpPrefix : temp;
            temp = getProperty("idp.server.callback");
            idpCallback = StringUtils.isEmpty(temp) ? idpCallback : temp;
            callbackUrl = idpProtocol + "://" + idpServer + idpPrefix + idpCallback;

            if (StringUtils.isEmpty(casServer)) {
                LOGGER.error(MISSING_CONFIG_MSG, "cas.server", propertiesFile);
                throw new IllegalArgumentException(
                        "CasLoginHandler missing properties needed to build the cas login URL in handler configuration.");
            }
            if (null == idpServer || "".equals(idpServer.trim())) {
                LOGGER.error(MISSING_CONFIG_MSG, "idp.server", propertiesFile);
                throw new IllegalArgumentException(
                        "CasLoginHandler missing properties needed to build the callback URL in handler configuration.");
            }
            setSupportsForceAuthentication(true);
            setSupportsPassive(true);

            if (StringUtils.isEmpty(casServer)) {
                LOGGER.error("Unable to start CasCallbackServlet. Verify that the IDP's web.xml file OR the external property is configured properly.");
                throw new ServletException(
                        "Missing casServer parameter to build the cas server URL - this is a required value");
            }
            casUrlPrefix = casProtocol + "://" + casServer + casPrefix;
            ticketValidator = new Cas20ServiceTicketValidator(casUrlPrefix);
            if (StringUtils.isEmpty(idpServer)) {
                LOGGER.error("Unable to start CasCallbackServlet. Verify that the IDP's web.xml file OR the external property is configured properly.");
                throw new ServletException(
                        "Missing idpServer parameter to build the idp server URL - this is a required value");
            }
            serverName = idpProtocol + "://" + idpServer;
            artifactParameterName = (StringUtils.isEmpty(artifactParamaterName) || "null".equals(artifactParamaterName)) ? "ticket"
                    : artifactParamaterName;
        } catch (FileNotFoundException ex) {
            java.util.logging.Logger.getLogger(CasMcbLoginHandler.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            java.util.logging.Logger.getLogger(CasMcbLoginHandler.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                reader.close();
            } catch (IOException ex) {
                java.util.logging.Logger.getLogger(CasMcbLoginHandler.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public String getCallbackUrl() {
        return callbackUrl;
    }

    public void setCallbackUrl(String callbackUrl) {
        this.callbackUrl = callbackUrl;
    }

    public String getCasLoginUrl() {
        return casLoginUrl;
    }

    public void setCasLoginUrl(String casLoginUrl) {
        this.casLoginUrl = casLoginUrl;
    }

    public String getCasProtocol() {
        return casProtocol;
    }

    public void setCasProtocol(String casProtocol) {
        this.casProtocol = casProtocol;
    }

    public String getCasPrefix() {
        return casPrefix;
    }

    public void setCasPrefix(String casPrefix) {
        this.casPrefix = casPrefix;
    }

    public String getCasServer() {
        return casServer;
    }

    public void setCasServer(String casServer) {
        this.casServer = casServer;
    }

    public String getIdpProtocol() {
        return idpProtocol;
    }

    public void setIdpProtocol(String idpProtocol) {
        this.idpProtocol = idpProtocol;
    }

    public String getIdpServer() {
        return idpServer;
    }

    public void setIdpServer(String idpServer) {
        this.idpServer = idpServer;
    }

    public String getIdpPrefix() {
        return idpPrefix;
    }

    public void setIdpPrefix(String idpPrefix) {
        this.idpPrefix = idpPrefix;
    }

    public String getIdpCallback() {
        return idpCallback;
    }

    public void setIdpCallback(String idpCallback) {
        this.idpCallback = idpCallback;
    }

    public Set<IParameterBuilder> getParameterBuilders() {
        return parameterBuilders;
    }

    public void setParameterBuilders(Set<IParameterBuilder> parameterBuilders) {
        this.parameterBuilders = parameterBuilders;
    }

    public String getArtifactParameterName() {
        return artifactParameterName;
    }

    public void setArtifactParameterName(String artifactParameterName) {
        this.artifactParameterName = artifactParameterName;
    }

    public String getCasToShibTranslatorNames() {
        return casToShibTranslatorNames;
    }

    public void setCasToShibTranslatorNames(String casToShibTranslatorNames) {
        this.casToShibTranslatorNames = casToShibTranslatorNames;
    }

    public String getServerName() {
        return serverName;
    }

    public void setServerName(String serverName) {
        this.serverName = serverName;
    }

    public Cas20ServiceTicketValidator getTicketValidator() {
        return ticketValidator;
    }

    public void setTicketValidator(Cas20ServiceTicketValidator ticketValidator) {
        this.ticketValidator = ticketValidator;
    }

    public Set<CasToShibTranslator> getTranslators() {
        return translators;
    }

    public void setTranslators(Set<CasToShibTranslator> translators) {
        this.translators = translators;
    }

    public String getPropertiesFile() {
        return propertiesFile;
    }

    public void setPropertiesFile(String propertiesFile) {
        this.propertiesFile = propertiesFile;
    }

    public Properties getProps() {
        return props;
    }

    public void setProps(Properties props) {
        this.props = props;
    }

}
