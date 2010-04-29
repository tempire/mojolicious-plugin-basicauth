use Mojo::IOLoop;
use Test::More;
use Test::Mojo;
use Mojo::ByteStream;

plan tests => 33;

# Test server
Mojo::IOLoop->new->generate_port;

# Lite app
use Mojolicious::Lite;

plugin 'basic_auth_condition';

get '/password_only' => ( basic_auth => 'password' ) => sub { shift->render_text('hello') };
get '/password_only';

get '/wordy' => ( basic_auth => {
        realm => 'realm', 
        username => 'username', 
        password => 'password'
    } ) => sub { shift->render_text( 'hello' ) };
get '/wordy';

get '/' => ( basic_auth => [ realm => username => 'password' ] ) => sub {
    shift->render_text( 'hello' );
};
get '/';



# Tests
my $client = app->client;
my $t = Test::Mojo->new;

# Tests for / and /wordy
foreach my $url ( qw| / /wordy /password_only | ) {

    diag "$url tests";

    # Password prompt
    $t->get_ok( $url )->
        status_is(401)->
        header_is( 'WWW-Authenticate' => "Basic realm='realm'" )->
        content_is('');
    
    # Invalid user/pass
    $t->get_ok( $url, { Authorization => "Basic fail" } )->
        header_is( 'WWW-Authenticate' => "Basic realm='realm'" )->
        status_is(401)->
        content_is('');

	# Different password for /password_only, test outside of loop
	next if $url eq '/password_only';
    
    # Valid user/pass
    my $encoded = Mojo::ByteStream->new( "username:password" )->b64_encode->to_string;
    chop $encoded;
    
    $t->get_ok( $url, { Authorization => "Basic $encoded" } )->
        status_is(200)->
        content_is('hello');
}

# /password_only valid password test

# Valid user/pass
my $encoded = Mojo::ByteStream->new( ":password" )->b64_encode->to_string;
chop $encoded;
$t->get_ok( '/password_only', { Authorization => "Basic $encoded" } )->
    status_is(200)->
    content_is( 'hello' );
