use Mojo::IOLoop;
use Test::More;
use Test::Mojo;
use Mojo::ByteStream 'b';

# Make sure sockets are working
plan tests => 45;

# Lite app
use Mojolicious::Lite;

# Silence
app->log->level('error');

plugin 'basic_auth';

get '/user-pass' => sub {
    my $self = shift;

    #return $self->render_text('denied')
    return $self->render(text => 'authorized')
      if $self->basic_auth(realm => username => 'password');

    $self->render( text => 'denied' );
};

get '/user-pass-with-colon-password' => sub {
    my $self = shift;

    return $self->render(text => 'authorized')
      if $self->basic_auth(realm => username => 'pass:word');

    $self->render( text => 'denied' );
};

get '/pass' => sub {
    my $self = shift;

    return $self->render( text => 'denied' )
      unless $self->basic_auth(realm => 'password');

    $self->render( text => 'authorized' );
};

# Entered user/pass supplied to callback
get '/get-auth-callback' => sub {
    my $self = shift;

    return $self->render( text => 'authorized' )
      if $self->basic_auth(
        realm => sub { return "@_" eq 'username password' });

    $self->render( text => 'denied' );
};

# Callback with colon in password
get '/get-auth-callback-with-colon-password' => sub {
    my $self = shift;

    return $self->render( text => 'authorized' )
      if $self->basic_auth(
        realm => sub { return "@_" eq 'username pass:word' });

    return $self->render( text => 'denied' );
};

under sub {
    my $self = shift;
    return $self->basic_auth(
        realm => sub { return "@_" eq 'username password' });
};

get '/under-bridge' => sub {
    shift->render(text => 'authorized');
};

# Tests
my $t = Test::Mojo->new;
my $encoded;


# Failures #

foreach (
    qw(
    /user-pass
    /pass
    /get-auth-callback
    )
  )
{

    # No user/pass
    $t->get_ok($_)->status_is(401)
      ->header_is('WWW-Authenticate' => 'Basic realm=realm')
      ->content_is('denied');

    # Incorrect user/pass
    $encoded = b('bad:auth')->b64_encode->to_string;
    chop $encoded;
    $t->get_ok($_, {Authorization => "Basic $encoded"})->status_is(401)
      ->header_is('WWW-Authenticate' => 'Basic realm=realm')
      ->content_is('denied');
}

# Under bridge fail
diag '/under-bridge';
$encoded = b("bad:auth")->b64_encode->to_string;
chop $encoded;
$t->get_ok('/under-bridge', {Authorization => "Basic $encoded"})
  ->status_is(401)->content_is('');

# Successes #

# Username, password
diag '/user-pass';
$encoded = b("username:password")->b64_encode->to_string;
chop $encoded;
$t->get_ok('/user-pass', {Authorization => "Basic $encoded"})->status_is(200)
  ->content_is('authorized');

# Username, password with colon in password
diag '/user-pass-with-colon-password';
$encoded = b("username:pass:word")->b64_encode->to_string;
chop $encoded;
$t->get_ok('/user-pass-with-colon-password', {Authorization => "Basic $encoded"})->status_is(200)
  ->content_is('authorized');

# Password only
diag '/pass';
$encoded = b(":password")->b64_encode->to_string;
chop $encoded;
$t->get_ok('/pass', {Authorization => "Basic $encoded"})->status_is(200)
  ->content_is('authorized');

# With callback
diag '/get-auth-callback';
$encoded = b("username:password")->b64_encode->to_string;
chop $encoded;
$t->get_ok('/get-auth-callback', {Authorization => "Basic $encoded"})
  ->status_is(200)->content_is('authorized');

# With callback and colon in password
diag '/get-auth-callback-with-colon-password';
$encoded = b("username:pass:word")->b64_encode->to_string;
chop $encoded;
$t->get_ok('/get-auth-callback-with-colon-password', {Authorization => "Basic $encoded"})
  ->status_is(200)->content_is('authorized');

# Under bridge
diag '/under-bridge';
$encoded = b("username:password")->b64_encode->to_string;
chop $encoded;
$t->get_ok('/under-bridge', {Authorization => "Basic $encoded"})
  ->status_is(200)->content_is('authorized');
