// Providers
var REG_NONE = NewRegistrar('none', 'NONE');    // No registrar.

var cloudflare = NewDnsProvider('cloudflare', 'CLOUDFLAREAPI');


// Default settings
DEFAULTS(
	NAMESERVER_TTL('1d'),
	DefaultTTL('1d'),
	AUTOSPLIT,              // Split long TXT
	CF_PROXY_DEFAULT_OFF    // Dont use Cloudflare-Proxy-Feature
);


// Zone-declaration
D('example.com', REG_NONE, DnsProvider(cloudflare));



// Include
//  (Do not touch unless you know what you are doing!)
require_glob("/app/hosts/");
