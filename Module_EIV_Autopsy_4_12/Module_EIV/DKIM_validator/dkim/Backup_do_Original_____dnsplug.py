# This software is provided 'as-is', without any express or implied
# warranty.  In no event will the author be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
# 2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
# 3. This notice may not be removed or altered from any source distribution.
#
# Copyright (c) 2008 Greg Hewgill http://hewgill.com
#
# This has been modified from the original software.
# Copyright (c) 2011 William Grant <me@williamgrant.id.au>


__all__ = [
    'get_txt'
    ]

def dns_provider():
    file = open("nameservers.csv","r")
    contents = file.read()[:-2]
    file.close()
    return contents.split(";")

def get_txt_dnspython(name, timeout=5):
    """Return a TXT record associated with a DNS name."""
    try:
      nameservers = dns_provider()
      if (len(nameservers)>0):
          dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
          dns.resolver.default_resolver.nameservers = nameservers

      a = dns.resolver.query(name, dns.rdatatype.TXT,raise_on_no_answer=False, lifetime=timeout)
      for r in a.response.answer:
          if r.rdtype == dns.rdatatype.TXT:
              return b"".join(r.items[0].strings)
    except dns.resolver.NXDOMAIN: pass
    return None


def get_txt_pydns(name, timeout=5):
    nameservers = dns_provider()
    if (len(nameservers)>0):
      dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
      dns.resolver.default_resolver.nameservers = nameservers

    """Return a TXT record associated with a DNS name."""
    # Older pydns releases don't like a trailing dot.
    if name.endswith('.'):
        name = name[:-1]
    response = DNS.DnsRequest(name, qtype='txt', timeout=timeout).req()
    if not response.answers:
        return None
    return b''.join(response.answers[0]['data'])


# No longer used since it doesn't support timeout
def get_txt_Milter_dns(name, timeout=5):
    """Return a TXT record associated with a DNS name."""
    # Older pydns releases don't like a trailing dot.
    if name.endswith('.'):
        name = name[:-1]
    sess = Session()
    a = sess.dns(name.encode('idna'),'TXT')
    if a: return b''.join(a[0])
    return None


# Prefer dnspython if it's there, otherwise use pydns.
try:
    import dns.resolver
    _get_txt = get_txt_dnspython
except ImportError:
    try:
        import DNS
        DNS.DiscoverNameServers()
        _get_txt = get_txt_pydns
    except:
        raise


def get_txt(name, timeout=5):
    """Return a TXT record associated with a DNS name.

    @param name: The bytestring domain name to look up.
    """
    # pydns needs Unicode, but DKIM's d= is ASCII (already punycoded).
    try:
        unicode_name = name.decode('UTF-8')
    except UnicodeDecodeError:
        return None
    txt = _get_txt(unicode_name, timeout)
    if type(txt) is str:
      txt = txt.encode('utf-8')
    return txt
