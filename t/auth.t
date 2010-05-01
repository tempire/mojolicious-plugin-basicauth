use Mojo::IOLoop;
use Test::More;
use Test::Mojo;
use Mojo::ByteStream;

plan tests => 21;

# Test server
Mojo::IOLoop->new->generate_port;

# Lite app
use Mojolicious::Lite;

plugin 'basic_auth';

get '/password_only' => sub {
	my $self = shift;
	
	$self->render_text( 'authenticated' ) 
		if $self->helper( basic_auth => 'password' );
};

get '/hashref' => sub {
	my $self = shift;
	
	$self->render_text( 'authenticated' )
		if $self->helper( basic_auth => {
        realm => 'realm', 
        username => 'username', 
        password => 'password'
    	} );
};

get '/user-pass' => sub {
	my $self = shift;
	
	$self->render_text( 'authenticated' )
		if $self->helper( basic_auth => username => 'password' );
};


# Tests
my $client = app->client;
my $t = Test::Mojo->new;
my $encoded;

# Password only #
diag '/password_only';

# Failure
$t->get_ok( '/password_only' )->
	status_is(401)->
	header_is( 'WWW-Authenticate' => 'Basic realm=' )->
	content_is('');

# Success
$encoded = Mojo::ByteStream->new( ":password" )->b64_encode->to_string;
chop $encoded;
$t->get_ok( '/password_only', { Authorization => "Basic $encoded" } )->
	status_is(200)->
	content_is('authenticated');


# Username, password, no realm #
diag '/user-pass';

# Failure
$t->get_ok( '/user-pass' )->
	status_is(401)->
	header_is( 'WWW-Authenticate' => 'Basic realm=' )->
	content_is('');

# Success
$encoded = Mojo::ByteStream->new( "username:password" )->b64_encode->to_string;
chop $encoded;
$t->get_ok( '/user-pass', { Authorization => "Basic $encoded" } )->
	status_is(200)->
	content_is('authenticated');


# Hashref #
diag '/hashref';

# Failure
$t->get_ok( '/hashref' )->
	status_is(401)->
	header_is( 'WWW-Authenticate' => 'Basic realm=realm' )->
	content_is('');

# Success
$encoded = Mojo::ByteStream->new( "username:password" )->b64_encode->to_string;
chop $encoded;
$t->get_ok( '/hashref', { Authorization => "Basic $encoded" } )->
	status_is(200)->
	content_is('authenticated');
