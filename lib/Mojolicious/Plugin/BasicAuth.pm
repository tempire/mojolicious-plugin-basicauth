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

			# No required credentials, return supplied auth to controller
			return $plugin->_supplied_auth( $auth ) if ! $password;

			return $self->res->code(200)
				if $callback and $callback->( $plugin->_supplied_auth( $auth ) );

			# Verify if supplied credentials
			my $encoded = Mojo::ByteStream->
				new( ($username||'') . ':' . ($password||'') )->
				b64_encode->
				to_string;
			chop $encoded;

			# Verified
			return $self->res->code(200) if $auth eq $encoded;

			# Not verified
			return $plugin->_password_prompt( $self, $realm );
		}
	);
}

sub _supplied_auth {
	my $self = shift;
	
	my @auth = split /:/, Mojo::ByteStream->new( shift )->
		b64_decode->
		to_string;

	return wantarray ?
		@auth :
		{ username => $auth[0], password => $auth[1] };
}

sub _expected_auth {
	my $self = shift;
	my $realm = shift;

	return @$realm{ qw/ realm password username / } if ref $realm eq "HASH";

	# realm, pass, user || realm, pass, undef
	return $realm, reverse @_;
}

sub _password_prompt {
	my ($self, $c, $realm) = @_;
	
	$c->res->headers->www_authenticate( 'Basic realm=' . ( $realm || '' ) );
	$c->res->code(401);

	return;
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
		...
	}

	
	# Mojolicious::Lite
	plugin 'basic_auth'
	
	get '/' => sub {
		my $self = shift;
		return unless $self->helper( basic_auth => realm => username => 'password' );
		
		# Username is optional:
		# $self->helper( basic_auth => realm => 'password' );
		...
	}

	# or, for more wordy configuration:
	get '/' => sub {
		my $self = shift;
		
		return unless
			$self->helper( basic_auth => {
				realm => 'realm',
				username => 'username',
				password => 'password'
			} );
	}


	# Advanced - verify credentials within the controller

	# With callback
	get '/' => sub {
		my $self = shift;

		return unless $self->helper( basic_auth => realm => sub {
			my ($username, $password) = @_;
			return $username eq 'username' and $password eq 'password';
		} );

		$self->render_text( 'authenticated' );
	};

	# Without callback
	get '/' => sub {
		return unless $self->helper( basic_auth => 'realm' );

		# Hashref or list (my @auth = ...)
		my $auth = $self->helper( basic_auth => 'realm' );
		return unless $auth;

		if( $auth->{username} eq 'username' and 
			$auth->{password} eq 'password' ) {

			$self->res->code(200);
			$self->render_text( 'authenticated' );
		}
	}

=head1 DESCRIPTION

L<Mojolicous::Plugin::BasicAuth> is a helper for basic http authentication.

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

Glen Hinkle L<glen@empireenterprises.com>

=cut
