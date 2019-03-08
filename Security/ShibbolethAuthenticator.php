<?php

namespace GaussAllianz\ShibbolethGuardBundle\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Psr\Log\LoggerInterface;
use GaussAllianz\ShibbolethGuardBundle\Security\ShibbolethUserProviderInterface;
use GaussAllianz\ShibbolethGuardBundle\Security\UsernameAttributeNotGivenException;
use Exception;

class ShibbolethAuthenticator extends AbstractGuardAuthenticator {

    private $handlerPath = '/Shibboleth.sso';
    private $sessionInitiatorPath = '/Login';
    private $usernameAttribute = 'Shib-Person-uid';
    private $attributeDefinitions = array(
        'uid' => array('header' => 'Shib-Person-uid', 'server' => 'uid', 'multivalue' => false),
        'cn' => array('header' => 'Shib-Person-commonName', 'server' => 'cn', 'multivalue' => false),
        'sn' => array('header' => 'Shib-Person-surname', 'server' => 'sn', 'multivalue' => false),
        'givenName' => array('header' => 'Shib-Person-givenName', 'server' => 'givenName', 'multivalue' => false),
        'mail' => array('header' => 'Shib-Person-mail', 'server' => 'mail', 'multivalue' => true),
        'ou' => array('header' => 'Shib-Person-ou', 'server' => 'ou', 'multivalue' => true),
        'telephoneNumber' => array('header' => 'Shib-Person-telephoneNumber', 'server' => 'telephoneNumber', 'multivalue' => true),
        'facsimileTelephoneNumber' => array('header' => 'Shib-Person-facsimileTelephoneNumber', 'server' => 'facsimileTelephoneNumber', 'multivalue' => true),
        'mobile' => array('header' => 'Shib-Person-mobile', 'server' => 'mobile', 'multivalue' => true),
        'postalAddress' => array('header' => 'Shib-Person-postalAddress', 'server' => 'postalAddress', 'multivalue' => true),
        'affiliation' => array('header' => 'Shib-EP-UnscopedAffiliation', 'server' => 'affiliation', 'multivalue' => true),
        'scopedAffiliation' => array('header' => 'Shib-EP-ScopedAffiliation', 'server' => 'scopedAffiliation', 'multivalue' => true),
        'orgUnitDN' => array('header' => 'Shib-EP-OrgUnitDN', 'server' => 'orgUnitDN', 'multivalue' => true),
        'orgDN' => array('header' => 'Shib-EP-OrgDN', 'server' => 'orgDN', 'multivalue' => false),
        'logoutURL' => array('header' => 'Shib-logoutURL', 'server' => 'logoutURL', 'multivalue' => false),
        'identityProvider' => array('header' => 'Shib-Identity-Provider', 'server' => 'Shib-Identity-Provider', 'multivalue' => false),
        'originSite' => array('header' => 'Shib-Origin-Site', 'server' => 'originSite', 'multivalue' => false),
        'authenticationInstant' => array('header' => 'Shib-Authentication-Instant', 'server' => 'authenticationInstant', 'multivalue' => false),
        'employeeType' => array('header' => 'Shib-KUL-employeeType', 'server' => 'employeeType', 'multivalue' => false),
        'studentType' => array('header' => 'Shib-KUL-studentType', 'server' => 'studentType', 'multivalue' => true),
        'primouNumber' => array('header' => 'Shib-KUL-PrimouNumber', 'server' => 'primouNumber', 'multivalue' => true),
        'ouNumber' => array('header' => 'Shib-KUL-ouNumber', 'server' => 'ouNumber', 'multivalue' => true),
        'dipl' => array('header' => 'Shib-KUL-dipl', 'server' => 'dipl', 'multivalue' => true),
        'opl' => array('header' => 'Shib-KUL-opl', 'server' => 'opl', 'multivalue' => true),
        'campus' => array('header' => 'Shib-KUL-campus', 'server' => 'campus', 'multivalue' => false),
        'logoutURL' => array('header' => 'Shib-logoutURL', 'server' => 'Shib-logoutURL', 'multivalue' => false),
        'applicationId' => array('header' => 'Shib-Application-Id', 'server' => 'Shib-Application-Id', 'multivalue' => false),
        'token' => array('header' => 'shib-session-id', 'server' => 'shib-session-id', 'multivalue' => false)
    );
    private $useHeaders = true;
    private $logger = null;
    private $supportSession = 'shib-session-id';

    /**
     * The constructor
     *
     * @param string $data_path The absolute path where to find the json data files.
     */
    public function __construct($handlerPath, $sessionInitiatorPath, $usernameAttribute, $attributeDefinitions = null, $useHeaders = true, LoggerInterface $logger) {
        $this->handlerPath = $handlerPath;
        $this->sessionInitiatorPath = $sessionInitiatorPath;
        $this->usernameAttribute = $usernameAttribute;
        if (is_array($attributeDefinitions)) {
            foreach ($attributeDefinitions as $name => $def) {
                $def['alias'] = $name;
                $this->addAttributeDefinition($def);
            }
        }
        $this->useHeaders = $useHeaders;
        $this->logger = $logger;
        $this->logger->debug("Created Shibboleth Guard Service");
    }

    /**
     * Called on every request. Return whatever credentials you want,
     * or null to stop authentication.
     */
    public function getCredentials(Request $request) {
        $this->logger->debug('[ShibbolethAuthenticator::getCredential]');
        if (!$this->hasAttribute($request, 'applicationId') || !((bool) $this->getAttribute($request, 'applicationId'))) {
            // User is not authenticated
            $this->logger->debug('[ShibbolethAuthenticator::getCredential] no shibsession in server variables');
            return;
        }

        // get all available attributes and deliver them with the credentials
        $credentials = array();
        foreach ($this->getAttributesDefinitions() as $attribute => $definition) {
            $credentials[$attribute] = $this->getAttribute($request, $attribute);
        }

        $this->logger->debug('[ShibbolethAuthenticator::getCredential] success ');
        // What you return here will be passed to getUser() as $credentials
        return $credentials;
    }

    public function getUser($credentials, UserProviderInterface $userProvider) {
        $this->logger->debug('[ShibbolethAuthenticator::getUser]');
        $username_attribute = $credentials[$this->usernameAttribute];

        // If the attribute was not given or is empty throw exception
        if (!$username_attribute || strlen($username_attribute) < 1) {
            $idp = $credentials['identityProvider'];
            throw new UsernameAttributeNotGivenException("The IdP '$idp' does not deliver the required username attribute.");
        }

        try {
            $user = $userProvider->loadUserByUsername($credentials);
        } catch (Exception $e) {
            try {
                $user = $userProvider->loadUserByUsername($credentials[$this->usernameAttribute]);
            } catch (Exception $ex) {
                $user = null;
            }
        }

        if ($user) {
            $this->logger->debug('[ShibbolethAuthenticator::getUser] success ' . $credentials[$this->usernameAttribute]);
            return $user;
        }

        $this->logger->debug('[ShibbolethAuthenticator::getUser] false return null');
        return null;
    }

    public function checkCredentials($credentials, UserInterface $user) {
        $this->logger->debug('[ShibbolethAuthenticator::checkCredentials] return true');
        // The credentials are always correct
        return true;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey) {
        $this->logger->debug('[ShibbolethAuthenticator::onAuthenticationSuccess]');
        // on success, let the request continue
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception) {
        $this->logger->debug('[ShibbolethAuthenticator::onAuthenticationFailure]');
        $this->logger->debug($exception->getMessage());

        $data = array(
            'message' => strtr($exception->getMessageKey(), $exception->getMessageData())

                // or to translate this message
                // $this->translator->trans($exception->getMessageKey(), $exception->getMessageData())
        );

        return new JsonResponse($data, Response::HTTP_FORBIDDEN);
    }

    /**
     * Called when authentication is needed, but it's not sent
     */
    public function start(Request $request, AuthenticationException $authException = null) {
        $this->logger->debug('[ShibbolethAuthenticator::start]');

        $data = array(
            // you might translate this message
            'message' => 'Authentication Required'
        );

        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
    }

    public function supportsRememberMe() {
        return false;
    }

    private function getAttributesDefinitions() {
        return $this->attributeDefinitions;
    }

    public function getAttribute($request, $attribute) {
        if ($this->useHeaders) {
            return $request->headers->get(strtolower($this->attributeDefinitions[$attribute]['header']), null);
        } else {
            $value = $request->server->get($this->attributeDefinitions[$attribute]['server'], null);
            if ($value === null) {
                $value = $request->server->get(str_replace('-', '_', $this->attributeDefinitions[$attribute]['server']), null);
            }
            return $value;
        }
    }

    private function hasAttribute($request, $attribute) {
        if ($this->useHeaders) {
            return $request->headers->has(strtolower($this->attributeDefinitions[$attribute]['header']));
        } else {
            $value = $request->server->has($this->attributeDefinitions[$attribute]['server']);
            if ($value === false) {
                $value = $request->server->has(str_replace('-', '_', $this->attributeDefinitions[$attribute]['server']));
            }
            return $value;
        }
    }

    /**
     * Returns URL to initiate login session. After successfull login, the user will be redirected
     * to the optional target page. The target can be an absolute or relative URL.
     *
     * @param string $targetUrl URL to redirect to after successfull login. Defaults to the current request URL.
     * @return string           The absolute URL to initiate a session
     */
    public function getLoginUrl(Request $request, $targetUrl = null) {
        // convert to absolute URL if not yet absolute.
        if (empty($targetUrl)) {
            $targetUrl = $request->getUri();
        }
        return $this->getHandlerURL($request) . $this->getSessionInitiatorPath() . '?target=' . urlencode($targetUrl);
    }

    public function getLogoutUrl(Request $request, $return = null) {
        $logout_redirect = $this->getAttribute($request, 'logoutURL');
        if (!empty($logout_redirect)) {
            return $this->getHandlerUrl($request) . '/Logout?return=' . urlencode($logout_redirect
                            . (empty($return) ? '' : '?return=' . $return));
        } elseif (!empty($return)) {
            return $this->getHandlerUrl($request) . '/Logout?return=' . urlencode($return);
        } else {
            return $this->getHandlerUrl($request) . '/Logout';
        }
    }

    public function getSessionInitiatorPath() {
        return $this->sessionInitiatorPath;
    }

    public function getHandlerUrl(Request $request) {
        return 'https://' . $request->getHost() . $this->handlerPath;
    }

    private function addAttributeDefinition($def) {
        if (!isset($def['multivalue'])) {
            $def['multivalue'] = false;
        }
        if (!isset($def['charset'])) {
            $def['charset'] = 'ISO-8859-1';
        }
        if ($def['server'] === NULL) {
            $def['server'] = $def['alias'];
        }
        $this->attributeDefinitions[$def['alias']] = $def;
    }

    /**
     * Called on every request to decide if this authenticator should be
     * used for the request. Returning false will cause this authenticator
     * to be skipped.
     */
    public function supports(Request $request): bool {
        return $request->headers->has($this->supportSession);
    }

}
