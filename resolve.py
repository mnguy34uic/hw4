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
    cache_key = (target_name, qtype)

    if cache_key in EXACT_CACHE:
        return EXACT_CACHE[cache_key]

    outbound_query = dns.message.make_query(target_name, qtype)
    outbound_query.flags &= ~dns.flags.RD

    servers = list(ROOT_SERVERS)
    best_zone = None

    for zone in INTERMEDIATE_CACHE:
        if target_name.is_subdomain(zone):
            if best_zone is None or len(zone) > len(best_zone):
                best_zone = zone

    if best_zone is not None:
        servers = INTERMEDIATE_CACHE[best_zone][:]

    queried = set()

    while servers:
        server = servers.pop(0)

        if server in queried:
            continue

        queried.add(server)

        try:
            response = dns.query.udp(outbound_query, server, timeout=3)
        except Exception:
            continue

        if response.rcode() == dns.rcode.NXDOMAIN:
            EXACT_CACHE[cache_key] = response
            return response

        if response.rcode() != dns.rcode.NOERROR:
            continue

        if not response.answer:
            has_soa = any(
                record.rdtype == dns.rdatatype.SOA
                for record in response.authority
            )

            if has_soa:
                EXACT_CACHE[cache_key] = response
                return response

        if response.answer:
            cname_target = None

            for answers in response.answer:
                for answer in answers:
                    if answer.rdtype == dns.rdatatype.CNAME:
                        cname_target = answer.target

            if cname_target:
                next_response = lookup(cname_target, qtype)

                for answers in response.answer:
                    if answers not in next_response.answer:
                        next_response.answer.insert(0, answers)

                EXACT_CACHE[cache_key] = next_response
                return next_response

            EXACT_CACHE[cache_key] = response
            return response

        new_servers = []
        ns_names = []
        referral_zone = None

        for record in response.authority:
            if record.rdtype == dns.rdatatype.NS:
                referral_zone = record.name
                for item in record:
                    ns_names.append(item.target)

        for ns_name in ns_names:
            found_glue = False

            for record in response.additional:
                if record.name == ns_name:
                    for item in record:
                        if item.rdtype == dns.rdatatype.A:
                            new_servers.append(str(item))
                            found_glue = True

            if not found_glue:
                ns_cache_key = (ns_name, dns.rdatatype.A)

                if ns_cache_key in EXACT_CACHE:
                    for answers in EXACT_CACHE[ns_cache_key].answer:
                        for answer in answers:
                            if answer.rdtype == dns.rdatatype.A:
                                new_servers.append(str(answer))
                    continue

                ns_query = dns.message.make_query(ns_name, dns.rdatatype.A)
                ns_query.flags &= ~dns.flags.RD

                ns_servers = list(ROOT_SERVERS)

                best_ns_zone = None

                for zone in INTERMEDIATE_CACHE:
                    if ns_name.is_subdomain(zone):
                        if best_ns_zone is None or len(zone) > len(best_ns_zone):
                            best_ns_zone = zone

                if best_ns_zone is not None:
                    ns_servers = INTERMEDIATE_CACHE[best_ns_zone][:]

                ns_queried = set()
                ns_ip_found = False

                while ns_servers and not ns_ip_found:
                    ns_server = ns_servers.pop(0)

                    if ns_server in ns_queried:
                        continue

                    ns_queried.add(ns_server)

                    try:
                        ns_response = dns.query.udp(ns_query, ns_server, timeout=3)
                    except Exception:
                        continue

                    if ns_response.answer:
                        for answers in ns_response.answer:
                            for answer in answers:
                                if answer.rdtype == dns.rdatatype.A:
                                    new_servers.append(str(answer))
                                    ns_ip_found = True

                        if ns_ip_found:
                            EXACT_CACHE[ns_cache_key] = ns_response
                            break

                    referral_ns_names = []

                    for record in ns_response.authority:
                        if record.rdtype == dns.rdatatype.NS:
                            for item in record:
                                referral_ns_names.append(item.target)

                    next_ns_servers = []

                    for record in ns_response.additional:
                        for item in record:
                            if item.rdtype == dns.rdatatype.A:
                                next_ns_servers.append(str(item))

                    if next_ns_servers:
                        ns_servers = next_ns_servers
                    else:
                        for referral_ns_name in referral_ns_names:
                            if referral_ns_name in NS_LOOKUPS_IN_PROGRESS:
                                continue

                            NS_LOOKUPS_IN_PROGRESS.add(referral_ns_name)

                            try:
                                ns_ip_response = lookup(referral_ns_name, dns.rdatatype.A)
                            finally:
                                NS_LOOKUPS_IN_PROGRESS.remove(referral_ns_name)

                            for answers in ns_ip_response.answer:
                                for answer in answers:
                                    if answer.rdtype == dns.rdatatype.A:
                                        next_ns_servers.append(str(answer))

                        if next_ns_servers:
                            ns_servers = next_ns_servers

        if new_servers:
            if referral_zone:
                INTERMEDIATE_CACHE[referral_zone] = new_servers[:]
            servers = new_servers

    failure_response = dns.message.make_response(outbound_query)
    failure_response.set_rcode(dns.rcode.SERVFAIL)
    return failure_response

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