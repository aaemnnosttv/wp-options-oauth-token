<?php

namespace OAuth\Common\Storage;

use OAuth\Common\Token\TokenInterface;
use OAuth\Common\Storage\Exception\TokenNotFoundException;
use OAuth\Common\Storage\Exception\AuthorizationStateNotFoundException;

/*
 * Stores a token as a WordPress option.
 */
class WP_Options implements TokenStorageInterface
{
    /**
     * @var string
     */
    protected $key;

    protected $stateKey;

    /**
     * @var object|\Redis
     */
    protected $redis;

    /**
     * @var object|TokenInterface
     */
    protected $cachedTokens;

    /**
     * @var object
     */
    protected $cachedStates;

    /**
     * @param string $key The key to store the token under in the options table
     * @param string $stateKey The key to store the state under in options table.
     */
    public function __construct($key, $stateKey)
    {
        $this->key = $key;
        $this->stateKey = $stateKey;
        $this->cachedTokens = array();
        $this->cachedStates = array();
    }

    /**
     * {@inheritDoc}
     */
    public function retrieveAccessToken($service)
    {
        if (!$this->hasAccessToken($service)) {
            throw new TokenNotFoundException('Token not found in wp_options');
        }

        if (isset($this->cachedTokens[$service])) {
            return $this->cachedTokens[$service];
        }

        return $this->cachedTokens[$service] = get_option("{$this->key}_{$service}");
    }

    /**
     * {@inheritDoc}
     */
    public function storeAccessToken($service, TokenInterface $token)
    {
        // (over)write the token
    	update_option("{$this->key}_{$service}", $token);
        $this->cachedTokens[$service] = $token;

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function hasAccessToken($service)
    {
        if (isset($this->cachedTokens[$service])
            && $this->cachedTokens[$service] instanceof TokenInterface
        ) {
            return true;
        }

        return get_option("{$this->key}_{$service}");
    }

    /**
     * {@inheritDoc}
     */
    public function clearToken($service)
    {
        delete_option("{$this->key}_{$service}");
        unset($this->cachedTokens[$service]);

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function clearAllTokens()
    {
        // memory
        $this->cachedTokens = array();

        // clear from db..
        // 
        // 

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function retrieveAuthorizationState($service)
    {
        if (!$this->hasAuthorizationState($service)) {
            throw new AuthorizationStateNotFoundException('State not found in wp_options');
        }

        if (isset($this->cachedStates[$service])) {
            return $this->cachedStates[$service];
        }

        return $this->cachedStates[$service] = get_option("{$this->stateKey}_{$service}");
    }

    /**
     * {@inheritDoc}
     */
    public function storeAuthorizationState($service, $state)
    {
        // (over)write the token
    	update_option("{$this->stateKey}_{$service}", $state);
        $this->cachedStates[$service] = $state;

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function hasAuthorizationState($service)
    {
        if (isset($this->cachedStates[$service])
            && null !== $this->cachedStates[$service]
        ) {
            return true;
        }

        return get_option("{$this->stateKey}_{$service}");
    }

    /**
     * {@inheritDoc}
     */
    public function clearAuthorizationState($service)
    {
        delete_option("{$this->stateKey}_{$service}");
        unset($this->cachedStates[$service]);

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function clearAllAuthorizationStates()
    {
        // memory
        $this->cachedStates = array();

        // clear from db..
        // 
        // 

        // allow chaining
        return $this;
    }

    /**
     * @return string $key
     */
    public function getKey()
    {
        return $this->key;
    }
}
