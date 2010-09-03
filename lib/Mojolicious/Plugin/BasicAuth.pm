package Mojolicious::Plugin::BasicAuth;

use strict;
use warnings;
use Mojo::ByteStream;

our $VERSION = '0.01';

use base 'Mojolicious::Plugin';

sub register {
	my ($plugin, $app) = @_;

	$app->renderer->add_helper(
		basic_auth => sub {
			my $self = shift;

			# Sent Credentials
			my $auth = $self->req->headers->authorization || '';
			$auth =~ s/^Basic //;

			# Required credentials
			my ($realm, $password, $username) = $plugin->_expected_auth( @_ );
			my $callback = $password if ref $password eq 'CODE';

			# No credentials entered
			return $plugin->_password_prompt( $self, $realm )
				if ! $auth and ! $callback;

			# Verification within callback
			return 1 if $callback
				and $callback->( $plugin->_supplied_auth( $auth ) );

			# Verify supplied credentials
			my $encoded = Mojo::ByteStream->
				new( ($username||'') . ':' . $password )->
				b64_encode->
				to_string;
			chop $encoded;

			# Verified
			return 1 if $auth eq $encoded;

			# Not verified
			return $plugin->_password_prompt( $self, $realm );
		}
	);
}

sub _supplied_auth {
	my $self = shift;
	
	return split /:/, Mojo::ByteStream->new( shift )->
		b64_decode->
		to_string;
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
		
=head2 Mojolicious

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
		
		$self->render_text( 'authenticated' );
	}

=head2 Mojolicious::Lite

	plugin 'basic_auth'
	
	get '/' => sub {
		my $self = shift;
		return unless $self->helper( basic_auth => realm => username => 'password' );
		
		# Username is optional:
		# $self->helper( basic_auth => realm => 'password' );
		
		$self->render_text( 'authenticated' );
	}

=head2 Hashref configuration

	# or, for more wordy configuration:
	get '/' => sub {
		my $self = shift;
		
		return unless
			$self->helper( basic_auth => {
				realm => 'realm',
				username => 'username',
				password => 'password'
			} );
		
		$self->render_text( 'authenticated' );
	}

=head2 Advanced usage - Verification in callback

	get '/' => sub {
		my $self = shift;

		return unless $self->helper( basic_auth => realm => sub {
			my ($username, $password) = @_;
			return 1 if $username eq 'username' and $password eq 'password';
		} );

		$self->render_text( 'authenticated' );
	};

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

0.01

=head1 AUTHOR

Glen Hinkle tempire@cpan.org

=cut
