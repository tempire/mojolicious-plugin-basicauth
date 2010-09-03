See pod for documentation, in lib/Mojolicious/Plugin/BasicAuth.pm

# Installation #

cpan Mojolicious::Plugin::BasicAuth

# Source #

git clone git://github.com/tempire/mojolicious-plugin-basicauth.git

# Basic Usage #

	use Mojolicious::Lite;
	plugin 'basic_auth'

	get '/' => sub {
	    my $self = shift;
	    $self->render_text('denied')
		 	unless $self->helper( basic_auth => realm => username => 'password' );
	    ...
	};

(See Mojolicious::Plugin::BasicAuth POD for more advanced usage)

# Credits #

* Sebastian Riedel for Mojolicious
  http://github.com/kraih/mojo.git

* Viacheslav Tykhanovskyi for spreading the love over IRC

* Both of the above for making #mojo a much less abrasive
  place than #catalyst
