package Mojolicious::Plugin::BasicAuth;

use strict;
use warnings;
use Mojo::ByteStream;

our $VERSION = '0.032';

use base 'Mojolicious::Plugin';

sub register {
	my ($plugin, $app) = @_;

	$app->renderer->add_helper(
		basic_auth => sub {
			my $self = shift;

			# Sent Credentials
			my $auth = $self->req->url->to_abs->userinfo || '';

			# Required credentials
			my ($realm, $password, $username) = $plugin->_expected_auth( @_ );
			my $callback = $password if ref $password eq 'CODE';

			# No credentials entered
			return $plugin->_password_prompt( $self, $realm )
				if ! $auth and ! $callback;

			# Verification within callback
			return 1 if $callback and $callback->( split /:/, $auth );

			# Verified with realm => username => password syntax
			return 1 if $auth eq ($username||'') . ":$password";

			# Not verified
			return $plugin->_password_prompt( $self, $realm );
		}
	);
}

sub _expected_auth {
	my $self = shift;
	my $realm = shift;

	return @$realm{ qw/ realm password username / } if ref $realm eq "HASH";

	# realm, pass, user || realm, pass, undef || realm, callback
	return $realm, reverse @_;
}

sub _password_prompt {
	my ($self, $c, $realm) = @_;
	
	$c->res->headers->www_authenticate( "Basic realm=$realm" );
	$c->res->code(401);

	return;
}

1;
__END__

=head1 NAME

Mojolicious::Plugin::BasicAuth - Basic HTTP Auth Helper

=head1 DESCRIPTION

L<Mojolicous::Plugin::BasicAuth> is a helper for basic http authentication.

=head1 USAGE

=head2 Callback

	use Mojolicious::Lite;

	plugin 'basic_auth';

	get '/' => sub {
		my $self = shift;

		my $callback = sub {
			my $username = shift || '';
			my $password = shift || '';
			return 1 $username eq 'username' and $password eq 'password';
		};

		return $self->render_text('denied') 
			unless $self->basic_auth( realm => $callback );

		$self->render_text('ok!');
	};

	app->start;

=head2 Alternate usage

		return $self->render_text('denied')
			unless $self->basic_auth( realm => username => 'password' );
		
		# Username is optional:
		# $self->basic_auth( realm => 'password' );
		
=head1 METHODS

L<Mojolicious::Plugin::BasicAuth> inherits all methods from
L<Mojolicious::Plugin> and implements the following new ones.

=head2 C<register>

    $plugin->register;

Register condition in L<Mojolicious> application.

=head1 SEE ALSO

L<Mojolicious>

=head1 DEVELOPMENT

L<http://github.com/tempire/mojolicious-plugin-basicauth>

=head1 VERSION

0.032

=head1 AUTHOR

Glen Hinkle tempire@cpan.org

=cut
