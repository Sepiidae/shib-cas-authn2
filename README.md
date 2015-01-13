## Shibboleth IdP External Authentication via CAS plugin

> A Shibboleth IdP v3.X plugin can be found at <https://github.com/Unicon/shib-cas-authn3>

This is a Shibboleth IDP external authentication plugin that delegates the authentication to the 
Central Authentication Server. The biggest advantage of using this component over the plain 
`REMOTE_USER` header solution provided by Shibboleth is the ability to utilize a full range 
of native CAS protocol features such as `renew` and `gateway`.

The plugin consists of 2 components:
* A custom Shibboleth `LoginHandler` to delegate to CAS, with support for both forced and passive authentication
* Shibboleth IDP Servlet acting as a bridge between CAS and IDP

Strategy for sharing state between CASified resource and IdP
-------------------------------------------------------------
This project provides a custom Shibboleth LoginHandler and servlet. The handler prepares the redirect to CAS and the servlet 
handles pulling out the authenticated username and passing that back to Shibboleth.

Build Status
-------------------------------------------------------------
Travis-CI: ![Travis-CI build status](https://travis-ci.org/Unicon/shib-cas-authn2.png)

Software Requirements
-------------------------------------------------------------

* This plugin will require Shibboleth Identity Provider v2.4.0 and above.

Configure, build, and deploy IdP external authentication plugin
---------------------------------------------------------------
The first step is to update your Shib idp deployment with the `CasCallbackServlet`. This can be done prior to building/deploying the idp war file or
if preferred, after the build, the files can be modified/updated in the war file before deploying to Tomcat. Previous instructions
were based on the idea that the files would be modified post-deployment. The recommended installation/deployment of the Shib idp suggest 
not exploding the Shib war, so these instructions assume you will modify the files ahead of time. 

### Overview

1. Update the Shib idb `web.xml` (adding the `CasCallbackServlet`). 
2. Configure the Shib idb `CasCallBackServlet` in the properties file
3. Update/configure the `handler.xml` file by adding the Cas `LoginHandler`
4. Build this project
5. Copy the resulting jar artifact to the idp library
6. Copy the cas client jar artifact to the idp library


### Changes to web.xml
Add the IDP External Authn Callback Servlet entry in `idp/WEB-INF/web.xml`

The servlet needs to be configured with either the init-param: `propertiesFile` (indicating the path and filename 
of an external properties file containing the name value parameters needed)

Example `web.xml`:

```xml
<!-- Servlet for receiving a callback from an external authentication system and continuing the IdP login flow -->
<servlet>
    <servlet-name>External Authn Callback</servlet-name>
    <servlet-class>net.unicon.idp.externalauth.CasCallbackServlet</servlet-class>
    <!--
        Parameters:
        **cas.server** is required. **cas.server.protocol** and **cas.server.prefix** are optional and default to 
        "https" and "/cas".
        **idp.server** is required. **idp.server.protocol** is optional and defaults to "https".
        **artifact.parameter.name** is optional and defaults to "ticket"

        Use the propertiesFile param to externalize the properties. If this is not set, the servlet will look
        in the default location (described below) for the properties. If the file doesn't exist or is not readable, 
        the servlet will attempt to initialize using defined init-params matching the desired properties.
    -->
    <init-param>
        <param-name>propertiesFile</param-name>
        <!-- 
            This can be any valid path and the name of the file can be whatever you prefer. Default value
            used if this parameter is not set is shown here.
        -->
        <param-value>/opt/shibboleth-idp/conf/cas-shib.properties</param-value>
    </init-param>
    <load-on-startup>2</load-on-startup>
</servlet>

<servlet-mapping>
    <servlet-name>External Authn Callback</servlet-name>
    <url-pattern>/Authn/Cas/*</url-pattern>
</servlet-mapping>
...
```

### Configure cas-shib.properties file

Configure the parameters for the properties file. [See the `cas-shib.properties.sample` file](https://github.com/Unicon/shib-cas-authn2/blob/master/cas-shib.properties.sample)
in this project for the full list. We suggest using this sample file as your template. Because the login handler and servlet share a set of properties we recommend using the externalized properties file for all your configuration needs.


### Changes to handler.xml
Modify the existing Shib handler.xml file with the following additions:

* Add the namespace and XSD path to the ph:ProfileHandlerGroup definition in `$IDP_HOME/conf/handler.xml`
Example:

```xml
<ph:ProfileHandlerGroup xmlns:ph="urn:mace:shibboleth:2.0:idp:profile-handler" 
                        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                        xmlns:shib-cas="http://unicon.net/shib-cas/authn"
                        xsi:schemaLocation="urn:mace:shibboleth:2.0:idp:profile-handler 
                        classpath:/schema/shibboleth-2.0-idp-profile-handler.xsd
                        http://unicon.net/shib-cas/authn
                        classpath:/schema/casLoginHandler.xsd">

...
```

* Add/Configure IDP External Login Handler in `$IDP_HOME/conf/handler.xml`
Example:

```xml
...

    <!-- propertiesFile attribute is optional - default value show here -->
    <ph:LoginHandler xsi:type="shib-cas:CasLoginHandler" 
                     propertiesFile="/opt/shibboleth-idp/conf/cas-shib.properties">
        <ph:AuthenticationMethod>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</ph:AuthenticationMethod>
        <!-- There may be 0..N paramBuilder entries. Each must list the fully qualified name 
             of the class to be added. 
        -->
        <shib-cas:paramBuilder class="net.unicon.idp.authn.provider.extra.EntityIdParameterBuilder" />
    </ph:LoginHandler>

...
```

To Build
--------

This project uses [Gradle](http://gradle.org) build system.

* In [`gradle.properties`](https://github.com/Unicon/shib-cas-authenticator/blob/master/gradle.properties), adjust
the property settings for the IdP path, version and Shibboleth common JAR file dependency version:

```properties
shibIdpVersion=2.4.0
shibCommonVersion=1.4.0
shibIdpPath=/opt/shibboleth-idp
```

* From the root directory, simply run `./gradlew`
* Copy `idp-cas-invoker/build/libs/idp-cas-invoker-x.x.jar` to `idp/WEB-INF/lib`
* Copy `idp-cas-invoker/build/libs/idp-cas-invoker-x.x.jar` to `/opt/shibboleth-idp/lib` (for `aacli.sh/.bat` functionality)
* Copy FROM CAS DEPLOYED WAR: `$CATALINA_HOME/webapps/cas/WEB-INF/lib/cas-client-core-[x.x.x].jar` to `idp/WEB-INF/lib`


Shibboleth IdP Upgrades
-------------------------------------------------------------

In order to properly protect the changes to the `web.xml` file of the Shibboleth IdP between upgrades, 
copy the changed version to the `conf` directory of the main Shib IdP directory (e.g. usually `/opt/shibboleth-idp/conf`).
Then, rebuild and redeploy the IdP as usual.

See the following links for additional info:
* https://wiki.shibboleth.net/confluence/display/SHIB2/IdPEnableECP
* https://wiki.shibboleth.net/confluence/display/SHIB2/IdPInstall [section: `Using a customized web.xml`)

Shibboleth SP Apache Configuration
-------------------------------------------------------------
* Ensure that the following command is set:
`ShibRequestSetting authnContextClassRef urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified`


New Features 2.0
-------------------------------------------------------------
* Externalized settings allow for setting the configuration of the callback servlet and login handler outside of the deployed IDP application.
* Default settings for as many of the parameters as possible has reduced the amount of items that have to be configured.
* Architecture now allows for pluggin of additional parameter builders. These builders can be added to send additional parameter information to CAS (such as the parameter in the form of the "entityId" param (relaying party id from Shib)).

Release Notes
-------------------------------------------------------------
v2.0.1
* Re-ordered the parameters sent to CAS. The original ordering meant that parameters would be added to the end of the params (thus looking like they were part of the callback service url). renew and/or gateway should be added first, followed by any additional built parameters, and concluded with the callback service url).

v2.0.2
* Fixed a bug where if the net.unicon.idp.authn.provider.extra.EntityIdParameterBuilder was manually added (this Builder is in the code by default), or added multiple times, the EntityId parameter would appear in the request multiple times.
* Updated the architecture to support developers writing their own extension to a new interface: CasToShibTranslator. This allows custom translation of CAS information for use in Shib. By default, the code will use the standard AuthenticatedNameTranslator which hands off the principal name (only) to Shib. Developers can add additional logic by implementing the net.unicon.idp.externalauth.CasToShibTranslator interface and then adding their class to the configuration thusly:
```
# Takes a comma separated list of fully qualified class names
casToShibTranslators=com.your.institution.MyCustomNamedTranslatorClass
```
v2.0.3
* Fixed a bug where the servlet init-params were not being read correctly.
* CAS login handler now implicitly supports both forced and passive authentication.

2.0.4
* Fixed a bug where the login handler wasn't properly reading whether to force authentication or whether passive (renew and gateway) should be passed to CAS. Previously the code was attempting to read this directly from the request parameters. Now the code is grabbing the login context set by Shib and asking directly.
