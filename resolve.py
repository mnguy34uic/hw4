"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

ROOT_SERVERS = ("198.41.0.4",
                "199.9.14.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")

EXACT_CACHE = {}
INTERMEDIATE_CACHE = {}
NS_LOOKUPS_IN_PROGRESS = set()

def collect_results(name: str) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    full_response = {}
    target_name = dns.name.from_text(name)

    # lookup CNAME
    response = lookup(target_name, dns.rdatatype.CNAME)
    cnames = []
    tmp = name
    for answers in response.answer:
        for answer in answers:
            cnames.append({"name": answer, "alias": tmp})
            tmp = answer

    # lookup A
    response = lookup(target_name, dns.rdatatype.A)
    arecords = []
    for answers in response.answer:
        a_name = answers.name
        for answer in answers:
            if answer.rdtype == 1:  # A record
                arecords.append({"name": a_name, "address": str(answer)})

    # lookup AAAA
    response = lookup(target_name, dns.rdatatype.AAAA)
    aaaarecords = []
    for answers in response.answer:
        aaaa_name = answers.name
        for answer in answers:
            if answer.rdtype == 28:  # AAAA record
                aaaarecords.append({"name": aaaa_name, "address": str(answer)})

    # lookup MX
    response = lookup(target_name, dns.rdatatype.MX)
    mxrecords = []
    for answers in response.answer:
        mx_name = answers.name
        for answer in answers:
            if answer.rdtype == 15:  # MX record
                mxrecords.append({"name": mx_name,
                                  "preference": answer.preference,
                                  "exchange": str(answer.exchange)})

    full_response["CNAME"] = cnames
    full_response["A"] = arecords
    full_response["AAAA"] = aaaarecords
    full_response["MX"] = mxrecords

    return full_response


def lookup(target_name: dns.name.Name,
           qtype: dns.rdata.Rdata) -> dns.message.Message:
    """
    This function uses a recursive resolver to find the relevant answer to the
    query.

    TODO: replace this implementation with one which asks the root servers
    and recurses to find the proper answer.
    """
    timeout = 3
    max_nested = 10

    cache_key = (target_name, qtype)

    if cache_key in EXACT_CACHE:
        return EXACT_CACHE[cache_key]

    outbound_query = dns.message.make_query(target_name, qtype)
    outbound_query.flags &= ~dns.flags.RD

    def failure():
        response = dns.message.make_response(outbound_query)
        response.set_rcode(dns.rcode.SERVFAIL)
        return response

    top_level = not NS_LOOKUPS_IN_PROGRESS

    if (cache_key in NS_LOOKUPS_IN_PROGRESS or len(NS_LOOKUPS_IN_PROGRESS) >= max_nested):
        return failure()

    queried = set()

    def handle_answer(response):
        owners = set()
        cname_targets = []

        for rrset in response.answer:
            owners.add(rrset.name)

            if rrset.rdtype == dns.rdatatype.CNAME:
                for item in rrset:
                    cname_targets.append(item.target)

        pending = [t for t in cname_targets if t not in owners]
        has_final = qtype != dns.rdatatype.CNAME and any(rrset.rdtype == qtype for rrset in response.answer)

        if has_final or not pending:
            return response

        next_response = lookup(pending[-1], qtype)

        combined = dns.message.make_response(outbound_query)
        combined.set_rcode(next_response.rcode())
        combined.answer = list(response.answer)

        for rrset in next_response.answer:
            if rrset not in combined.answer:
                combined.answer.append(rrset)

        combined.authority = list(next_response.authority)

        return combined

    def query_servers(servers):
        for server in servers:
            if server in queried:
                continue

            queried.add(server)

            try:
                response = dns.query.udp(outbound_query, server, timeout=timeout)
            except Exception:
                continue

            if response.rcode() == dns.rcode.NXDOMAIN:
                return response
            if response.rcode() != dns.rcode.NOERROR:
                continue

            if response.answer:
                return handle_answer(response)

            if any(r.rdtype == dns.rdatatype.SOA for r in response.authority):
                return response

            referral_zone = None
            ns_names = []

            for rrset in response.authority:
                if rrset.rdtype == dns.rdatatype.NS:
                    referral_zone = rrset.name

                    for item in rrset:
                        ns_names.append(item.target)

            if (referral_zone is None or not target_name.is_subdomain(referral_zone)):
                continue

            glue = []
            unglue = []

            for ns_name in ns_names:
                addresses = []

                for rrset in response.additional:
                    if (rrset.name == ns_name and rrset.rdtype == dns.rdatatype.A):
                        addresses.extend(str(item) for item in rrset)

                if addresses:
                    for address in addresses:
                        if address not in glue:
                            glue.append(address)
                else:
                    unglue.append(ns_name)

            if glue:
                INTERMEDIATE_CACHE[referral_zone] = list(glue)
                result = query_servers(glue)

                if result is not None:
                    return result

            for ns_name in unglue:
                if (ns_name, dns.rdatatype.A) in NS_LOOKUPS_IN_PROGRESS:
                    continue

                ns_response = lookup(ns_name, dns.rdatatype.A)

                addresses = []

                for rrset in ns_response.answer:
                    if rrset.rdtype == dns.rdatatype.A:
                        addresses.extend(str(item) for item in rrset)

                if not addresses:
                    EXACT_CACHE[(ns_name, dns.rdatatype.A)] = ns_response
                    continue

                known = INTERMEDIATE_CACHE.setdefault(referral_zone, [])

                for address in addresses:
                    if address not in known:
                        known.append(address)

                result = query_servers(addresses)

                if result is not None:
                    return result

        return None

    NS_LOOKUPS_IN_PROGRESS.add(cache_key)

    try:
        best_zone = None

        for zone in INTERMEDIATE_CACHE:
            if target_name.is_subdomain(zone):
                if best_zone is None or len(zone) > len(best_zone):
                    best_zone = zone

        if best_zone is not None and INTERMEDIATE_CACHE[best_zone]:
            start_servers = list(INTERMEDIATE_CACHE[best_zone])
        else:
            start_servers = list(ROOT_SERVERS)

        result = query_servers(start_servers)
    finally:
        NS_LOOKUPS_IN_PROGRESS.discard(cache_key)

    if result is None:
        result = failure()

        if top_level:
            EXACT_CACHE[cache_key] = result

        return result

    EXACT_CACHE[cache_key] = result
    return result

def print_results(results: dict) -> None:
    """
    take the results of a `lookup` and print them to the screen like the host
    program would.
    """

    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


def main():
    """
    if run from the command line, take args and call
    printresults(lookup(hostname))
    """
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()
    for a_domain_name in program_args.name:
        print_results(collect_results(a_domain_name))

if __name__ == "__main__":
    main()