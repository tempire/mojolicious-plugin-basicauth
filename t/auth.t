use Mojo::IOLoop;
use Test::More;
use Test::Mojo;
use Mojo::ByteStream;

# Make sure sockets are working
plan skip_all => 'working sockets required for this test!'
	unless Mojo::IOLoop->new->generate_port; # Test server
plan tests => 44;

# Lite app
use Mojolicious::Lite;

# Silence
app->log->level('error');

plugin 'basic_auth';

get '/user-pass' => sub {
	my $self = shift;
	
	$self->render_text( 'authenticated' )
		if $self->helper( basic_auth => realm => username => 'password' );
};

get '/pass' => sub {
	my $self = shift;
	
	$self->render_text( 'authenticated' ) 
		if $self->helper( basic_auth => 'realm' => 'password' );
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

# Entered user/pass supplied to callback
get '/get-auth-callback' => sub {
	my $self = shift;

	return unless $self->helper( basic_auth => realm => sub {
		my ($username, $password) = @_;
		return 1 if @_ == 2 and 
			$username eq 'username' and 
			$password eq 'password';
	} );

	$self->render_text( 'authenticated' );
};

# Tests
my $client = app->client;
my $t = Test::Mojo->new;
my $encoded;


# Failures #

foreach( qw( 
	/user-pass
	/pass
	/hashref
	/get-auth-callback
	) ) {

	# No user/pass
	$t->get_ok( $_ )->
		status_is(401)->
		header_is( 'WWW-Authenticate' => 'Basic realm=realm' )->
		content_is('');

	# Incorrect user/pass
	$encoded = Mojo::ByteStream->new( 'bad:auth' )->b64_encode->to_string;
	chop $encoded;
	$t->get_ok( $_, { Authorization => "Basic $encoded" } )->
		status_is(401)->
		header_is( 'WWW-Authenticate' => 'Basic realm=realm' )->
		content_is('');
}

# Successes #

# Username, password
diag '/user-pass';
$encoded = Mojo::ByteStream->new( "username:password" )->b64_encode->to_string;
chop $encoded;
$t->get_ok( '/user-pass', { Authorization => "Basic $encoded" } )->
	status_is(200)->
	content_is('authenticated');

# Password only
diag '/pass';
$encoded = Mojo::ByteStream->new( ":password" )->b64_encode->to_string;
chop $encoded;
$t->get_ok( '/pass', { Authorization => "Basic $encoded" } )->
	status_is(200)->
	content_is('authenticated');

# Hashref
diag '/hashref';
$encoded = Mojo::ByteStream->new( "username:password" )->b64_encode->to_string;
chop $encoded;
$t->get_ok( '/hashref', { Authorization => "Basic $encoded" } )->
	status_is(200)->
	content_is('authenticated');

# With callback
diag '/get-auth-callback';
$encoded = Mojo::ByteStream->new( "username:password" )->b64_encode->to_string;
chop $encoded;
$t->get_ok( '/get-auth-callback', { Authorization => "Basic $encoded" } )->
	status_is(200)->
	content_is('authenticated');
