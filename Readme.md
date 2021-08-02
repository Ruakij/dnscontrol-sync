# Dnscontrol-Sync

This image is designed to synchronise changes between Nameserver-Providers (like PowerDNS or Cloudflare-DNS).

It uses [dnscontrol](https://github.com/StackExchange/dnscontrol) to pull & push these changes
and DNS-NOTIFY for event-driven updates.

---

## Current state

At the moment, this program can only pull changes from PowerDns and will push it to any other provider specified for that domain in `dnsconfig.js` (from dnscontrol).

Furthermore there is an option to auto-rename a zone (e.g. public-zone has suffix .public), because e.g. PowerDns does not support "views".

It is very likely the software will make mistakes when multiple change-events were executed when the first one was not finished yet.
It's planned to have a queue for that.

---

## How it works

PowerDns has this program as "slave" and will send a DNS-NOTIFY when zone-information has changed.
We will then use dnscontrol to pull the whole zone into a dnscontrol-formatted JavaScript-file,
modify it to match our needs and push it using the configured dnscontrol config.

### In Short

1. DNS-NOTIFY by PowerDns
2. dnscontrol get-zones PowerDns
3. Modify generated file
4. dnscontrol push

---

## Which Providers are supported

Check out the dnscontrol-documentation for further information about providers, setup and compatability of special records and settings:

https://stackexchange.github.io/dnscontrol/provider-list