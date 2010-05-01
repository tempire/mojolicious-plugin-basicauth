use Mojo::IOLoop;
use Test::More;
use Test::Mojo;
use Mojo::ByteStream;

# Make sure sockets are working
plan skip_all => 'working sockets required for this test!'
  unless Mojo::IOLoop->new->generate_port; # Test server
plan tests => 28;

# Lite app
use Mojolicious::Lite;

# Silence
app->log->level('error');

plugin 'basic_auth';

get '/realm-user-pass' => sub {
	my $self = shift;
	
	$self->render_text( 'authenticated' )
		if $self->helper( basic_auth => realm => username => 'password' );
};

get '/user-pass' => sub {
	my $self = shift;
	
	$self->render_text( 'authenticated' )
		if $self->helper( basic_auth => username => 'password' );
};

get '/pass' => sub {
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


# Tests
my $client = app->client;
my $t = Test::Mojo->new;
my $encoded;

# Realm, username, and password #
diag '/realm-user-pass';

# Failure
$t->get_ok( '/realm-user-pass' )->
	status_is(401)->
	header_is( 'WWW-Authenticate' => 'Basic realm=realm' )->
	content_is('');

# Success
$encoded = Mojo::ByteStream->new( "username:password" )->b64_encode->to_string;
chop $encoded;
$t->get_ok( '/realm-user-pass', { Authorization => "Basic $encoded" } )->
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


# Password only #
diag '/pass';

# Failure
$t->get_ok( '/pass' )->
	status_is(401)->
	header_is( 'WWW-Authenticate' => 'Basic realm=' )->
	content_is('');

# Success
$encoded = Mojo::ByteStream->new( ":password" )->b64_encode->to_string;
chop $encoded;
$t->get_ok( '/pass', { Authorization => "Basic $encoded" } )->
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
