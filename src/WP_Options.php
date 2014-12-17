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
        $this->keyChain = "_keychain_$key";
        $this->stateChain = "_statechain_$stateKey";
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
        $this->addToChain($service, $this->keyChain);

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
        $this->clearFromChain($service, $this->keyChain);

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function clearAllTokens()
    {
        if ( $keychain = get_option($this->keyChain) )
        {
            foreach ($keychain as $key)
                delete_option($key);
        }

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
        $this->addToChain($service, $this->stateChain);

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
        $this->clearFromChain($service, $this->stateChain);

        // allow chaining
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function clearAllAuthorizationStates()
    {
        if ( $statechain = get_option($this->stateChain) )
        {
            foreach ($statechain as $stateKey)
                delete_option($stateKey);
        }

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

    protected function addToChain($key, $collection)
    {
        $chain = get_option($collection, array());

        if ( ! in_array($key, $chain) )
        {
            $chain[] = $key;
            update_option($collection, $chain);
        }
    }

    protected function clearFromChain($key, $collection)
    {
        $chain = get_option($collection, array());

        if ( in_array($key, $chain) )
        {
            $i = array_search($key, $chain);
            unset($chain[ $i ]);
            update_option($collection, $chain);
        }
    }
}
