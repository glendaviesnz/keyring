<?php

define( 'KEYRING__LINKEDINOAUTH2_ID',     KEYRING__LINKEDIN_ID );
define( 'KEYRING__LINKEDINOAUTH2_KEY',    KEYRING__LINKEDIN_KEY );
define( 'KEYRING__LINKEDINOAUTH2_SECRET', KEYRING__LINKEDIN_SECRET );

// To use company pages, you need to request the`rw_company_admin` scope during authentication.
class Keyring_Service_LinkedIn extends Keyring_Service_OAuth2 {
	const NAME  = 'linkedin';
	const LABEL = 'LinkedIn';

	var $person = array();

	// self_url and self_method are defined by Keyring_Service->set_endpoint()

	/**
	 * Keyring_Service_LinkedIn constructor.
	 */
	function __construct() {
		parent::__construct();

		$this->set_endpoint( 'authorize',    'https://www.linkedin.com/oauth/v2/authorization', 'GET' );
		$this->set_endpoint( 'access_token', 'https://www.linkedin.com/oauth/v2/accessToken',   'POST' );
		$this->set_endpoint( 'self',         'https://api.linkedin.com/v2/me',            'GET' );
		$this->set_endpoint( 'profile_pic',  'https://api.linkedin.com/v2/me/picture-urls::(original)/', 'GET' );

		$creds        = $this->get_credentials();
		$this->app_id = $creds['app_id'];
		$this->key    = $creds['key'];
		$this->secret = $creds['secret'];

		$this->consumer             = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method     = new OAuthSignatureMethod_HMAC_SHA1;
		$this->authorization_header = 'Bearer';

		// Filter to conditionally set the scope for a company page admin.
		add_filter( 'keyring_' . self::NAME . '_request_scope', array( $this, 'member_permissions' ) );
	}

	/**
	 * Add in the `scope` parameter when authorizing.
	 * r_liteprofile   Grants access to first name, last name, id, and profile picture.
	 * w_member_social Grants access to post on behalf of the user.
	 *
	 * @param string $scope
	 * @return string
	 */
	function member_permissions( $scope ) {
		$scope = 'r_liteprofile w_member_social';
		return $scope;
	}

	/**
	 * By adding the `x-li-format: json` header here, we can avoid having to append `?format=json` to all requests.
	 *
	 * https://developer.linkedin.com/docs/rest-api#hero-par_longformtext_4_longform-text-content-par_resourceparagraph
	 *
	 * @param string $url
	 * @param array $params
	 * @return array|Keyring_Error|mixed|object|string
	 */
	function request( $url, array $params = array() ) {
		$params['headers']['x-li-format'] = 'json';
		return parent::request( $url, $params );
	}

	/**
	 * Build the meta for the token.
	 *
	 * @param mixed $token
	 * @return false|int|mixed
	 */
	function build_token_meta( $token ) {
		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				$token['access_token'],
				array()
			)
		);

		$response = $this->request(
			$this->self_url . '?projection=(id,firstName,lastName,profilePicture(displayImage~:playableStreams))',
			array( 'method' => $this->self_method )
		);

		if ( Keyring_Util::is_error( $response ) ) {
			$meta = array();
		} else {
			$this->person = $response;

			$firstName = $this->person->firstName;
			$lastName  = $this->person->lastName;
			$lfirst = "{$firstName->preferredLocale->language}_{$firstName->preferredLocale->country}";
			$llast  = "{$lastName->preferredLocale->language}_{$lastName->preferredLocale->country}";

			$profilePicture = $this->person->profilePicture;

			$meta = array(
				'user_id' => $this->person->id,
				'name'    => $firstName->localized->{$lfirst} . ' ' . $lastName->localized->{$llast},
				'picture' => $profilePicture->{'displayImage~'}->elements[0]->identifiers[0]->identifier,
			);
		}

		return apply_filters( 'keyring_access_token_meta', $meta, self::NAME, $token, $response, $this );
	}

	/**
	 * Get profile picture.
	 *
	 * @return string|mixed
	 */
	function fetch_profile_picture () {
		$response = $this->request(
			$this->self_url . '?projection=(profilePicture(displayImage~:playableStreams))',
			[ 'method' => $this->self_method ]
		);

		if ( Keyring_Util::is_error( $response ) ) {
			return new WP_Error( 'missing-profile_picture', 'Could not find profile picture.' );
		}

		return $response->profilePicture->{'displayImage~'}->elements[0]->identifiers[0]->identifier;
	}

	/**
	 * Test whether the connection has not been voided or expired.
	 *
	 * @return array|bool|Keyring_Error|mixed|object|string
	 */
	function test_connection() {
		$res = $this->request(
			$this->self_url,
			array( 'method' => $this->self_method )
		);
		if ( ! Keyring_Util::is_error( $res ) ) {
			return true;
		}
		return $res;
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_LinkedIn', 'init' ) );
