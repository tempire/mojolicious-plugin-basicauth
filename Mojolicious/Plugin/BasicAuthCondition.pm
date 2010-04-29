package Mojolicious::Plugin::BasicAuthCondition;

use strict;
use warnings;
use Data::Dumper;
#use MIME::Base64 qw/ encode_base64 /;
use Mojo::ByteStream;

use base 'Mojolicious::Plugin';

sub register {
	my ($plugin, $app) = @_;

	$app->routes->add_condition(
		basic_auth => sub {
			my ($r, $tx, $captures, $args) = @_;

			# Required credentials
			my ($realm, $username, $password) = $plugin->_expected_auth( $args );

			# Sent Credentials
			my $auth = $tx->req->headers->authorization || '';
			$auth =~ s/^Basic //;

			# Verify
			my $encoded = Mojo::ByteStream->new( "$username:$password" )->
				b64_encode->
				to_string;

			chop $encoded;

			$tx->res->code(200) and return $captures if $auth eq $encoded;

			# Not verified
			$plugin->_password_prompt( $tx, $realm );
		}
	);
}

sub _expected_auth {
	my ($self, $args) = @_;
	
	return @$args if ref $args eq "ARRAY";

	return @$args{ qw/ realm username password / } if ref $args eq "HASH";
	
	# Only password supplied
	return 'realm', '', $args;
}

sub _password_prompt {
	my ($self, $tx, $realm) = @_;

	$tx->res->headers->www_authenticate( "Basic realm='$realm'" );
	$tx->res->code(401);
}

1;
__END__

=head1 NAME

Mojolicious::Plugin::BasicAuthCondition - Basic HTTP Auth Condition Plugin

=head1 SYNOPSIS

    # Mojolicious
    $self->plugin('basic_auth_condition');
    my $r = $self->routes;

    my $auth = $r->route->over(basic_auth => realm => username => 'password');
    $auth->route('/:controller/:action')

    # Mojolicious::Lite
    plugin 'basic_auth_condition';
    get '/' => ( basic_auth => [ realm => username => 'password' ] ) => sub {...};
    get '/'; # Capture unauthorized requests

    # or, for more wordy configuration:
    get '/' => (basic_auth => {
        realm => 'realm',
        username => 'username',
        password => 'password'
    } ) => sub {...};
    get '/'; # Capture unauthorized requests

    
    # To supply only a password (no username)
    get '/' => ( basic_auth => 'password' ) => sub {...};
    get '/'; # Capture unauthorized requests

=head1 DESCRIPTION

L<Mojolicous::Plugin::BasicAuthCondition> is a routes condition for basic http authentication
based routes.

All Mojolicious::Lite actions with basic_auth_condition must have a follow 
through action to capture processing for unauthorized requests.

=head1 METHODS

L<Mojolicious::Plugin::BasicAuthCondition> inherits all methods from
L<Mojolicious::Plugin> and implements the following new ones.

=head2 C<register>

    $plugin->register;

Register condition in L<Mojolicious> application.

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Guides>, L<http://mojolicious.org>.

=cut
