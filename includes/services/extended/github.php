<?php

/**
 * Github service definition for Keyring.
 * https://developer.github.com/apps/building-oauth-apps/
 */

class Keyring_Service_GitHub extends Keyring_Service_OAuth2 {
	const NAME  = 'github';
	const LABEL = 'GitHub';

	function __construct() {
		parent::__construct();

		$this->set_endpoint( 'authorize',    'https://github.com/login/oauth/authorize',    'GET' );
		$this->set_endpoint( 'access_token', 'https://github.com/login/oauth/access_token', 'POST' );
		$this->set_endpoint( 'self',         'https://api.github.com/user',                 'GET' );

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->authorization_header = 'token';
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_GitHub', 'init' ) );
