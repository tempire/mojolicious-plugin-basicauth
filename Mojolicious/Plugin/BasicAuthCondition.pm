package Mojolicious::Plugin::BasicAuth;

use strict;
use warnings;
use Data::Dumper;
use Mojo::ByteStream;

use base 'Mojolicious::Plugin';

sub register {
	my ($plugin, $app) = @_;

	$app->renderer->add_helper(
		basic_auth => sub {
			my $self = shift;

			# Required credentials
			my ($password, $username, $realm) = $plugin->_expected_auth( @_ );

			# Sent Credentials
			my $auth = $self->req->headers->authorization || '';
			$auth =~ s/^Basic //;

			# Verify
			my $encoded = Mojo::ByteStream->new( "$username:$password" )->
				b64_encode->
				to_string;

			chop $encoded;

			# Verified
			return $self->res->code(200) if $auth eq $encoded;

			# Not verified
			$plugin->_password_prompt( $self, $realm );

			return;
		}
	);
}

sub _expected_auth {
	my ($self, $args) = @_;

	my @args;
	
	return @$args{ qw/ password username realm / } if ref $args eq "HASH";

	return reverse splice @_, 1;
}

sub _password_prompt {
	my ($self, $c, $realm) = @_;
	
	$c->res->headers->www_authenticate( 'Basic realm=' . ( $realm || '' ) );
	$c->res->code(401);
}

1;
__END__

=head1 NAME

Mojolicious::Plugin::BasicAuth - Basic HTTP Auth Helper

=head1 SYNOPSIS

	# Mojolicious
	package MyApp;
	
	sub startup {
		 my $self = shift;
		 $self->plugin('basic_auth');
		 ...
	 }
    
	 package MyApp::Controller;
	 
	 sub index {
		 my $self = shift;
		 return unless $self->helper( basic_auth => realm => username => 'password' );
	 }

	# Mojolicious::Lite
	plugin 'basic_auth'
	get '/' => sub {
		my $self = shift;
		$self->render_text( 'authenticated' )
			if $self->helper( basic_auth => realm => username => 'password' );
	}

	# or, for more wordy configuration:
	get '/' => sub {
		my $self = shift;
		$self->helper( basic_auth => {
			realm => 'realm',
			username => 'username',
			password => 'password'
		} );
	}

	# Realm and username are optional:
	$self->helper( basic_auth => username => 'password' );
	$self->helper( basic_auth => 'password' );

=head1 DESCRIPTION

L<Mojolicous::Plugin::BasicAuth> is a helper for basic http authentication.

=head1 METHODS

L<Mojolicious::Plugin::BasicAuth> inherits all methods from
L<Mojolicious::Plugin> and implements the following new ones.

=head2 C<register>

    $plugin->register;

Register condition in L<Mojolicious> application.

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Guides>, L<http://mojolicious.org>.

=head1 DEVELOPMENT

http://github.com/tempire/mojolicious-plugin-basicauthcondition

=head1 AUTHOR

Glen Hinkle, glen@empireenterprises.com

=cut
