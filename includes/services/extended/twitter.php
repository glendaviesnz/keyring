<?php

/**
 * Twitter service definition for Keyring. Clean implementation of OAuth1
 */

class Keyring_Service_Twitter extends Keyring_Service_OAuth1 {
	const NAME  = 'twitter';
	const LABEL = 'Twitter';

	function __construct() {
		parent::__construct();

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_twitter_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_twitter_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$this->authorization_header = true;
		$this->authorization_realm  = "twitter.com";

		$this->set_endpoint( 'request_token', 'https://twitter.com/oauth/request_token', 'POST' );
		$this->set_endpoint( 'authorize',     'https://twitter.com/oauth/authorize',     'GET'  );
		$this->set_endpoint( 'access_token',  'https://twitter.com/oauth/access_token',  'POST' );
		$this->set_endpoint( 'verify',        'https://api.twitter.com/1.1/account/verify_credentials.json', 'GET' );
		$this->set_endpoint( 'user_info',     'https://api.twitter.com/1.1/users/show.json', 'GET' );

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		// WPCOM -- SEE BELOW
		$this->set_keys( $this->app_id, $this->key, $this->secret );

		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->requires_token( true );
	}

	/**
	 * WPCOM
	 * Hackity hackity hack!
	 *
	 * Once Keyring and its services are loaded, there's no way to tell it to use a different set of keys.
	 * Normally we want to use the Publicize Twitter application but for the @automattic/automatticians list sync,
	 * we need to use a different app. Due to protected variables elsewhere in Keyring, the consumer variable
	 * must be set within this class rather than externally. So where we are with this hack.
	 *
	 * It'd be a really bad idea to call this method outside of an async job because you could break
	 * Publicize and stuff like that since Keyring runs in a single-instance. Async jobs are okay because they
	 * die after the job runs which means the polluted keys won't affect normal Keyring usage.
	 *
	 * Questions about this lame hack? Ask Alex Mills.
	 */
	function set_keys( $app_id, $key, $secret ) {
		$this->app_id  = $app_id;
		$this->key     = $key;
		$this->secret  = $secret;

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
	}

	function parse_response( $response ) {
		return json_decode( $response );
	}

	function build_token_meta( $token ) {
		// Set the token so that we can make requests using it
		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				new OAuthToken(
					$token['oauth_token'],
					$token['oauth_token_secret']
				)
			)
		);

		$response = $this->request( $this->verify_url, array( 'method' => $this->verify_method ) );
		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			$meta = array(
				'user_id'    => $token['user_id'],
				'username'   => $token['screen_name'],
				'name'       => $response->name,
				'picture'    => str_replace( '_normal.', '.', $response->profile_image_url ),
				'_classname' => get_called_class(),
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta, 'twitter', $token, $response, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return '@' . $token->get_meta( 'username' );
	}

	function test_connection() {
			$res = $this->request( $this->verify_url, array( 'method' => $this->verify_method ) );
			if ( !Keyring_Util::is_error( $res ) )
				return true;

			// Twitter may return a rate limiting error if the user accesses the sharing settings or post
			// page frequently. If so, ignore that error, things are likely aaaa-okay...
			$keyring_error_message = $res->get_error_message();
			if ( is_array( $keyring_error_message ) && isset( $keyring_error_message['response']['code'] ) ) {
				if ( 429 == absint( $keyring_error_message['response']['code'] ) ) {
					return true;
				}
			}

			return $res;
	}

	function fetch_profile_picture() {
		$res = $this->request( add_query_arg( array( 'user_id' => $this->token->get_meta( 'external_id' ) ), $this->user_info_url ), array( 'method' => $this->user_info_method ) );
		if ( Keyring_Util::is_error( $res ) )
			return $res;

		return empty( $res->profile_image_url_https ) ? null : esc_url_raw( str_replace( '_normal', '', $res->profile_image_url_https ) ); // large size https://dev.twitter.com/overview/general/user-profile-images-and-banners
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Twitter', 'init' ) );
