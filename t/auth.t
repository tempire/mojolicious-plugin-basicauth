use Mojo::IOLoop;
use Test::More;
use Test::Mojo;
use MIME::Base64 qw/ encode_base64 /;

plan tests => 24;

# Test server
Mojo::IOLoop->new->generate_port;

# Lite app
use Mojolicious::Lite;

plugin 'basic_auth_condition';

get '/' => ( basic_auth => [ realm => username => 'password' ] ) => sub {
    shift->render_text( 'hello' );
};

get '/wordy' => ( basic_auth => {
        realm => 'realm', 
        username => 'username', 
        password => 'password'
    } ) => sub { shift->render_text( 'hello' ) };

get '/password_only' => ( basic_auth => 'password' ) => sub { shift->render_text( 'hello' ) };


# Tests
my $client = app->client;
my $t = Test::Mojo->new;

# Tests for / and /wordy
foreach my $url ( qw| / /wordy | ) {

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
    
    
    # Valid user/pass
    my $encoded = encode_base64( "username:password", '' );
    
    $t->get_ok( $url, { Authorization => "Basic $encoded" } )->
        status_is(200)->
        content_is('hello');
}


# Test for /password_only
diag "/password_only tests";

# Valid user/pass
my $encoded = encode_base64( ':password', '' );

$t->get_ok( '/password_only', { Authorization => "Basic $encoded" } )->
    status_is(200)->
    content_is('hello');

