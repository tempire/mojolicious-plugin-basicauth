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
			
			# Get required credentials
			my ($realm, $username, $password) = $plugin->_expected_auth( @_ );

			# No credentials entered
			return $plugin->_password_prompt( $self, $realm ) if ! $auth;

			# No required credentials, return supplied auth to application
			return $plugin->_supplied_auth( $auth ) 
				if ! $username and ! $password;

			# Verify if supplied credentials
			my $encoded = Mojo::ByteStream->
				new( ($username||'') . ':' . ($password||'') )->
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

	return @$realm{ qw/ realm username password / } if ref $realm eq "HASH";

	# realm, user, pass
	return $realm, @_ if @_ == 2;
	
	# realm, pass
	return $realm, undef, @_;
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

	# Username is optional:
	$self->helper( basic_auth => realm => 'password' );

	# To compare credentials within the controller
	get '/' => sub {
		return unless $self->helper( basic_auth => 'realm' );

		my $auth = $self->helper( basic_auth => 'realm' );
		# Also works with a list:
		# my @auth = $self->helper( basic_auth => 'realm' );

		# No credentials supplied by user
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

L<http://github.com/tempire/mojolicious-plugin-basicauthcondition>

=head1 VERSION

0.01

=head1 AUTHOR

Glen Hinkle L<glen@empireenterprises.com>

=cut
