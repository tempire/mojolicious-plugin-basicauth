See pod for documentation, in lib/Mojolicious/Plugin/BasicAuth.pm

# Installation #

cpan Mojolicious::Plugin::BasicAuth

# Source #

git clone git://github.com/tempire/mojolicious-plugin-basicauth.git

# With callback #

	use Mojolicious::Lite;
	plugin 'basic_auth'

	get '/' => sub {
		my $self = shift;

		my $callback = sub {
			my ($username, $password) = @_;
			return 1 if $self->verify_in_database($username, $password)
		};

		$self->render_text('denied')
			unless $self->basic_auth( realm => $callback );

		$self->render_text('authenticated');
	};

# Alternate simple usage #

		$self->render_text('denied')
			unless $self->basic_auth( realm => username => 'password' );
		
		# Username is optional:
		# $self->basic_auth( realm => 'password' );

(See Mojolicious::Plugin::BasicAuth POD for more advanced usage)

# Credits #

* Sebastian Riedel for Mojolicious
  http://github.com/kraih/mojo.git

* Viacheslav Tykhanovskyi for spreading the love over IRC

* Both of the above for making #mojo a much less abrasive
  place than #catalyst
