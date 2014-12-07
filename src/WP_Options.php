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
     * @param string $key The key to store the token under in the options table
     * @param string $stateKey The key to store the state under in options table.
     */
    public function __construct($key, $stateKey)
    {
        $this->key = $key;
        $this->stateKey = $stateKey;
    }

    /**
     * {@inheritDoc}
     */
    public function retrieveAccessToken($service)
    {
        if (!$this->hasAccessToken($service)) {
            throw new TokenNotFoundException('Token not found in wp_options');
        }

        return get_option("{$this->key}_{$service}");
    }

    /**
     * {@inheritDoc}
     */
    public function storeAccessToken($service, TokenInterface $token)
    {
        // (over)write the token
    	update_option("{$this->key}_{$service}", $token);

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function hasAccessToken($service)
    {
        return (get_option("{$this->key}_{$service}") instanceof TokenInterface);
    }

    /**
     * {@inheritDoc}
     */
    public function clearToken($service)
    {
        delete_option("{$this->key}_{$service}");

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function clearAllTokens()
    {
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

        return get_option("{$this->stateKey}_{$service}");
    }

    /**
     * {@inheritDoc}
     */
    public function storeAuthorizationState($service, $state)
    {
        // (over)write the token
    	update_option("{$this->stateKey}_{$service}", $state);

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function hasAuthorizationState($service)
    {
        return (bool) get_option("{$this->stateKey}_{$service}");
    }

    /**
     * {@inheritDoc}
     */
    public function clearAuthorizationState($service)
    {
        delete_option("{$this->stateKey}_{$service}");

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function clearAllAuthorizationStates()
    {
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
