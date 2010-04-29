package Mojolicious::Plugin::BasicAuthCondition;

use strict;
use warnings;
use Data::Dumper;
use MIME::Base64 qw/ encode_base64 /;

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
			my $encoded = encode_base64( "$username:$password", '' ); 
			return $captures if $auth eq $encoded;

			# Not verified
			$plugin->_password_prompt( $tx, $realm );
		}
	);
}

sub _expected_auth {
	my ($self, $args) = @_;
	
	return @$args if ref $args eq "ARRAY";

	return @$args{ qw/ realm username password / };
}

sub _password_prompt {
	my ($self, $tx, $realm) = @_;

	$tx->res->headers->www_authenticate( "Basic realm='$realm'" );
	$tx->res->code(404);
	#$tx->render;
}

1;
__END__

=head1 NAME

Mojolicious::Plugin::BasicAuthCondition - Basic HTTP Auth Condition Plugin

=head1 SYNOPSIS

    # Mojolicious
    $self->plugin('basic_auth_condition');
    $self->routes->route('/:controller/:action')->over(basic_auth => realm => username => 'password');

    # Mojolicious::Lite
    plugin 'basic_auth_condition';
    get '/' => (basic_auth => [ realm => username => 'password' ] ) => sub {...};

    # or, for more specific (and wordy) configuration:
    get '/' => (basic_auth => {
        realm => 'realm',
        username => 'username',
        password => 'password'
    } ) => sub {...};

=head1 DESCRIPTION

L<Mojolicous::Plugin::BasicAuthCondition> is a routes condition for basic http authentication
based routes.

=head1 METHODS

L<Mojolicious::Plugin::BasicAuthCondition> inherits all methods from
L<Mojolicious::Plugin> and implements the following new ones.

=head2 C<register>

    $plugin->register;

Register condition in L<Mojolicious> application.

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Guides>, L<http://mojolicious.org>.

=cut
