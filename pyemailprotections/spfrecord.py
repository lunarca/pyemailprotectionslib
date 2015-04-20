import re
import dns.resolver


class NoSpfRecordException(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class SpfRecord(object):

    def __init__(self):
        self.version = None
        self.record = None
        self.mechanisms = None
        self.all_string = None

    @staticmethod
    def from_spf_string(spf_string):
        spf_record = SpfRecord()
        spf_record.record = spf_string
        spf_record.mechanisms = _extract_spf_mechanisms(spf_string)
        # TODO: Add from_spf_string method

    @staticmethod
    def from_domain(domain):
        return SpfRecord.from_spf_string(get_spf_record(domain))


def _get_redirect_mechanism_domain(spf_mechanisms):
    redirect_domain = None
    for mechanism in spf_mechanisms:
        redirect_mechanism = re.match('redirect=(.*)', mechanism)
        if redirect_mechanism is not None:
            redirect_domain = redirect_mechanism.group(1)
    return redirect_domain


def _get_redirected_spf_mechanisms(redirect_domain):
    spf_record = get_spf_record(redirect_domain)
    return _extract_spf_mechanisms(spf_record)


def _find_unique_mechanisms(initial_mechanisms, redirected_mechanisms):
    return [x for x in redirected_mechanisms if x not in initial_mechanisms]


def _extract_spf_mechanisms(spf_string):
    spf_mechanism_pattern = ("(?:((?:\+|-|~)?(?:a|mx|ptr|include"
                             "|ip4|ip6|exists|redirect|exp|all)"
                             "(?:(?::|/)?(?:\S*))?) ?)")
    spf_mechanisms = re.findall(spf_mechanism_pattern, spf_string)

    redirect_domain = _get_redirect_mechanism_domain(spf_mechanisms)

    if redirect_domain is not None:
        redirected_mechanisms = _get_redirected_spf_mechanisms(redirect_domain)
        spf_mechanisms.extend(_find_unique_mechanisms(spf_mechanisms, redirected_mechanisms))

    return spf_mechanisms


def _match_spf_record(txt_record):
    spf_pattern = re.compile('^"(v=spf.*)"')
    potential_spf_match = spf_pattern.match(str(txt_record))
    return potential_spf_match


def _find_spf_record_from_answers(txt_records):
    spf_record = None
    for record in txt_records:
        potential_match = _match_spf_record(record)
        if potential_match is not None:
            spf_record = potential_match.group(1)
    return spf_record


def get_spf_record(domain):
    try:
        txt_records = dns.resolver.query(domain, "TXT")
        return _find_spf_record_from_answers(txt_records)
    except dns.resolver.NoAnswer:
        return None
