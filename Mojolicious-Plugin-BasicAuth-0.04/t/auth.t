use Mojo::IOLoop;
use Test::More;
use Test::Mojo;
use Mojo::ByteStream;

# Make sure sockets are working
plan skip_all => 'working sockets required for this test!'
  unless Mojo::IOLoop->new->generate_port;    # Test server
plan tests => 39;

# Lite app
use Mojolicious::Lite;

# Silence
app->log->level('error');

plugin 'basic_auth';

get '/user-pass' => sub {
    my $self = shift;

    #return $self->render_text('denied')
    return $self->render(text => 'denied')
      unless $self->basic_auth(realm => username => 'password');

    $self->render_text('authorized');
};

get '/pass' => sub {
    my $self = shift;

    return $self->render_text('denied')
      unless $self->basic_auth(realm => 'password');

    $self->render_text('authorized');
};

# Entered user/pass supplied to callback
get '/get-auth-callback' => sub {
    my $self = shift;

    return $self->render_text('denied')
      unless $self->basic_auth(
        realm => sub { return 1 if "@_" eq 'username password' });

    $self->render_text('authorized');
};

under sub {
    my $self = shift;
    return $self->basic_auth(
        realm => sub { return 1 if "@_" eq 'username password' });
};

get '/under-bridge' => sub {
    shift->render(text => 'authorized');
};

# Tests
my $client = app->client;
my $t      = Test::Mojo->new;
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
    $encoded = Mojo::ByteStream->new('bad:auth')->b64_encode->to_string;
    chop $encoded;
    $t->get_ok($_, {Authorization => "Basic $encoded"})->status_is(401)
      ->header_is('WWW-Authenticate' => 'Basic realm=realm')
      ->content_is('denied');
}

# Under bridge fail
diag '/under-bridge';
$encoded = Mojo::ByteStream->new("bad:auth")->b64_encode->to_string;
chop $encoded;
$t->get_ok('/under-bridge', {Authorization => "Basic $encoded"})
  ->status_is(401)->content_is('');

# Successes #

# Username, password
diag '/user-pass';
$encoded = Mojo::ByteStream->new("username:password")->b64_encode->to_string;
chop $encoded;
$t->get_ok('/user-pass', {Authorization => "Basic $encoded"})->status_is(200)
  ->content_is('authorized');

# Password only
diag '/pass';
$encoded = Mojo::ByteStream->new(":password")->b64_encode->to_string;
chop $encoded;
$t->get_ok('/pass', {Authorization => "Basic $encoded"})->status_is(200)
  ->content_is('authorized');

# With callback
diag '/get-auth-callback';
$encoded = Mojo::ByteStream->new("username:password")->b64_encode->to_string;
chop $encoded;
$t->get_ok('/get-auth-callback', {Authorization => "Basic $encoded"})
  ->status_is(200)->content_is('authorized');

# Under bridge
diag '/under-bridge';
$encoded = Mojo::ByteStream->new("username:password")->b64_encode->to_string;
chop $encoded;
$t->get_ok('/under-bridge', {Authorization => "Basic $encoded"})
  ->status_is(200)->content_is('authorized');

