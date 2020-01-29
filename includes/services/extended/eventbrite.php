<?php

/**
 * Eventbrite service definition for Keyring.
 * http://developer.eventbrite.com/
 */

class Keyring_Service_Eventbrite extends Keyring_Service_OAuth2 {
	const NAME = 'eventbrite';
	const LABEL = 'Eventbrite';
	const API_BASE = 'https://www.eventbriteapi.com/v3/';
	const OAUTH_BASE = 'https://www.eventbrite.com/oauth/';

	function __construct() {
		parent::__construct();

		add_action( 'keyring_connection_verified', array( $this, 'keyring_connection_verified' ), 1, 3 );
		add_action( 'keyring_connection_deleted', array( $this, 'keyring_connection_deleted' ), 1, 2 );

		add_filter( 'keyring_' . $this->get_name() . '_request_token_params', array( $this, 'add_connection_referrer' ) );

		$this->set_endpoint( 'authorize', self::OAUTH_BASE . 'authorize', 'GET' );
		$this->set_endpoint( 'access_token', self::OAUTH_BASE . 'token', 'POST' );
		$this->set_endpoint( 'self', self::API_BASE . 'users/me/', 'GET' );

		// Enable "basic" UI for entering key/secret
		if ( ! KEYRING__HEADLESS_MODE ) {
			add_action( 'keyring_eventbrite_manage_ui', array( $this, 'basic_ui' ) );
			add_filter( 'keyring_eventbrite_basic_ui_intro', array( $this, 'basic_ui_intro' ) );
		}

		$creds = $this->get_credentials();
		$this->app_id  = $creds['app_id'];
		$this->key     = $creds['key'];
		$this->secret  = $creds['secret'];

		$this->consumer = new OAuthConsumer( $this->key, $this->secret, $this->callback_url );
		$this->signature_method = new OAuthSignatureMethod_HMAC_SHA1;

		$this->authorization_header    = 'Bearer';
		$this->authorization_parameter = false;
	}

	function keyring_connection_verified( $service, $id, $request_token ) {
		if ( 'eventbrite' != $service || 'eventbrite' != $request_token->token['for'] )
			return;

		update_blog_option( absint( $request_token->token['blog_id'] ), 'eventbrite_api_token', absint( $id ) );
	}

	function keyring_connection_deleted( $service, $request ) {
		if ( 'eventbrite' != $service )
			return;

		delete_blog_option( absint( $request['blog'] ), 'eventbrite_api_token' );
	}

	/**
	 * Append a referrer to the oAuth request made to Eventbrite, at their request
	 *
	 * See http://themedevp2.wordpress.com/2013/12/05/can-we-add-refwpoauth-to/
	 *
	 * @param array $params
	 * @filter keyring_eventbrite_request_token_params
	 * @return array
	 */
	public function add_connection_referrer( $params ) {
		if ( ! isset( $params['ref'] ) ) {
			$params['ref'] = 'wpoauth';
		}

		return $params;
	}

	function basic_ui_intro() {
		echo '<p>' . sprintf( __( "To get started, <a href='https://www.eventbrite.com/api/key'>register an OAuth client on Eventbrite</a>. The most important setting is the <strong>OAuth redirect_uri</strong>, which should be set to <code>%s</code>. You can set the other values to whatever you like.", 'keyring' ), esc_url(  Keyring_Util::admin_url( 'eventbrite', array( 'action' => 'verify' ) ) ) ) . '</p>';
		echo '<p>' . __( "Once you've saved those changes, copy the <strong>APPLICATION KEY</strong> value into the <strong>API Key</strong> field, then click the 'Show' link next to the <strong>OAuth client secret</strong>, copy the value into the <strong>API Secret</strong> field and click save (you don't need an App ID value for Eventbrite).", 'keyring' ) . '</p>';
	}

	function build_token_meta( $token ) {
		$this->set_token(
			new Keyring_Access_Token(
				$this->get_name(),
				$token['access_token'],
				array()
			)
		);
		$response = $this->request( $this->self_url, array( 'method' => $this->self_method ) );
		$meta = array();
		if ( ! Keyring_Util::is_error( $response ) ) {
			if ( isset( $response->emails->email ) ) {
				$meta['username'] = $response->emails->email;
			}

			if ( isset( $response->id ) ) {
				$meta['user_id'] = $response->id;
			}

			if ( isset( $response->name ) ) {
				$meta['name'] = $response->name;
			}
		}

		return apply_filters( 'keyring_access_token_meta', $meta, 'eventbrite', $token, null, $this );
	}

	function get_display( Keyring_Access_Token $token ) {
		return $token->get_meta( 'name' );
	}

	function create_webhook( Keyring_Access_Token $token ) {
		global $keyring_request_token;
		$eventbrite_webhook_id = $token->get_meta( 'eventbrite_webhook_id' );

		if ( null === $eventbrite_webhook_id ) {
			$params = array( 'endpoint_url' => 'https://public-api.wordpress.com/eventbrite/?eb_blog_id=' . $keyring_request_token->meta['blog_id'] . '\u0026eb_user_id=' . $keyring_request_token->meta['user_id'] );
			$results = $this->request( add_query_arg( $params, 'https://www.eventbriteapi.com/v3/webhooks/' ), array( 'method' => 'POST' ) );

			if ( ! Keyring_Util::is_error( $results ) ) {
				return (int) $results->id;
			} else {
				return false;
			}
		}
	}
}

add_action( 'keyring_load_services', array( 'Keyring_Service_Eventbrite', 'init' ) );

// Eventbrite WPCOM specific stuff

function keyring_eventbrite_delete_connection( $service, $request ) {
	global $wpdb;
	$id = $request['token' ];

	if ( 'eventbrite' != $service )
		return;

	if ( ! wp_verify_nonce( $request['kr_nonce'], 'keyring-delete' ) || ! wp_verify_nonce( $request['nonce'], 'keyring-delete-eventbrite-'. absint( $id ) ) )
		wp_die( "Cheatin' huh?" );

	$wpdb->delete( 'external_access_tokens', array( 'user_id' => get_current_user_id(), 'id' => absint( $id ) ) );

	if ( empty( $_GET['eventbrite_widget_id'] ) ) {
		$redirect_to = add_query_arg( array(
			'page' => 'theme-options-page'
		), get_admin_url( absint( $request['blog'] ), 'themes.php' ) );
	} else {
		$redirect_to = add_query_arg( array(
			'eventbrite_widget_id' => absint( $_GET['eventbrite_widget_id'] )
		), get_admin_url( absint( $request['blog'] ), 'widgets.php' ) );
	}

	wp_safe_redirect( $redirect_to );
	exit();
}
add_action( 'keyring_connection_deleted', 'keyring_eventbrite_delete_connection', 10, 2 );

/**
 * When a Keyring connection is validated and verified, this function watches for connections
 * that were initiated by this plugin's widget and in those cases redirects from public-api.wordpress.com
 * back to the blog's widgets admin page along with some parameters that tell the widget
 * in question to open (slide down) itself.
 *
 * "keyring_verified_redirect" seems like a better hook to use for this but Publicize hooks into
 * "keyring_connection_verified" (which this function is also hooked into) and will fatal here
 * if this function doesn't run first.
 *
 * @param string $service The service name.
 * @param string $id The token ID.
 * @param Keyring_Request_Token $request_token The request token used during the authentication process.
 */
function keyring_eventbrite_redirect( $service, $id, $request_token ) {
	if ( 'eventbrite' != $service || 'eventbrite' != $request_token->token['for'] )
		return;

	if ( empty( $_GET['eventbrite_widget_id'] ) ) {
		$redirect_to = add_query_arg( array(
			'page'     => 'theme-options-page',
			'token_id' => $id,
		), get_admin_url( $request_token->token['blog_id'], 'themes.php' ) );
	} else {
		$redirect_to = add_query_arg( array(
			'eventbrite_widget' => 'connection_verified',
			'eventbrite_widget_id' => absint( $_GET['eventbrite_widget_id'] ),
			'token_id' => $id,
		), get_admin_url( $request_token->token['blog_id'], 'widgets.php' ) );
	}

	wp_safe_redirect( $redirect_to );
	exit();
}
add_action( 'keyring_connection_verified', 'keyring_eventbrite_redirect', 4, 3 );

/**
 * This changes the blog ID in the Keyring token from that of public-api.wordpress.com to the correct blog ID.
 *
 * @see wpcom_keyring_get_blog_id_from_request_and_verify()
 *
 * @param int $id The current value for the blog ID (probably that of public-api.wordpress.com)
 * @param array $request A copy of $_REQUEST.
 * @return int The corrected blog ID if the Keyring request is ours, otherwise the original $id value.
 */
function keyring_eventbrite_set_blog_id( $id, $request ) {
	return wpcom_keyring_get_blog_id_from_request_and_verify( 'eventbrite', $id, $request );
}
add_filter( 'keyring_request_blog_id', 'keyring_eventbrite_set_blog_id', 10, 2 );
