import dns.resolver
import dns.query
import dns.zone

resolver = dns.resolver.Resolver(configure=False)

def query_dns(domain, record_type=dns.rdatatype.ANY, nameservers=['8.8.8.8', '8.8.4.4']):
    resolver.nameservers = nameservers
    try:
        return [answer.to_text() for answer in resolver.resolve(domain, record_type)]
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.NXDOMAIN:
        print(f"Domain \"{domain}\" does not exist.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def get_aaaa_records(domain, nameservers=['8.8.8.8', '8.8.4.4']):
    aaaa_records = query_dns(domain, dns.rdatatype.AAAA, nameservers)
    if aaaa_records:
        return aaaa_records
    ns_records = query_dns(domain, dns.rdatatype.NS, nameservers)
    if ns_records is None:
        print("No NS records found.")
        return None
    for ns_name in ns_records:
        ns_ip = query_dns(ns_name, dns.rdatatype.A)
        if ns_ip:
            aaaa_records_from_ns = query_dns(domain, dns.rdatatype.AAAA, [str(ns_ip[0])])
            if aaaa_records_from_ns:
                return aaaa_records_from_ns

    print("No AAAA records found on NS servers either.")
    return None

