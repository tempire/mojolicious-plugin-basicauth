See pod for documentation, in lib/Mojolicious/Plugin/BasicAuth.pm

# Installation

cpan Mojolicious::Plugin::BasicAuth

# Source

git clone git://github.com/tempire/mojolicious-plugin-basicauth.git

# Usage

## Callback

	use Mojolicious::Lite;

	plugin 'basic_auth';

	get '/' => sub {
		my $self = shift;

		return unless $self->basic_auth( realm => sub {
			my ($user, $pass) = @_;
			return 1 if $user eq 'user' and $pass eq 'pass';
		} );

		$self->render_text('authenticated');
	};

## Alternate usage

		return unless $self->basic_auth( realm => user => 'pass' );
		
		# User is optional:
		# $self->basic_auth( realm => 'pass' );

(See Mojolicious::Plugin::BasicAuth POD for more advanced usage)

# Credits

* Sebastian Riedel for Mojolicious
  http://github.com/kraih/mojo.git

* Viacheslav Tykhanovskyi for spreading the love over IRC

* Both of the above for making #mojo a much less abrasive
  place than #catalyst
