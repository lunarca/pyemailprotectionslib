import re
import dns.resolver
import logging


class NoDmarcRecordException(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class DmarcRecord(object):

    def __init__(self):
        self.version = None
        self.policy = None
        self.pct = None
        self.rua = None
        self.ruf = None
        self.subdomain_policy = None
        self.dkim_alignment = None
        self.spf_alignment = None
        self.record = None

    def __str__(self):
        return self.record

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def _store_tag_data(self, tag_name, tag_value):
        if tag_name == "v":
            self.version = tag_value
        elif tag_name == "p":
            self.policy = tag_value
        elif tag_name == "pct":
            self.pct = tag_value
        elif tag_name == "rua":
            self.rua = tag_value
        elif tag_name == "ruf":
            self.ruf = tag_value
        elif tag_name == "sp":
            self.subdomain_policy = tag_value
        elif tag_name == "adkim":
            self.dkim_alignment = tag_value
        elif tag_name == "aspf":
            self.spf_alignment = tag_value

    def process_tags(self, dmarc_string):
        TAG_NAME, TAG_VALUE = (0, 1)
        tags = _extract_tags(dmarc_string)
        for tag in tags:
            self._store_tag_data(tag[TAG_NAME], tag[TAG_VALUE])

    @staticmethod
    def from_dmarc_string(dmarc_string):
        if dmarc_string is not None:
            dmarc_record = DmarcRecord()
            dmarc_record.record = dmarc_string
            dmarc_record.process_tags(dmarc_string)
            return dmarc_record
        else:
            return None

    @staticmethod
    def from_domain(domain):
        dmarc_string = get_dmarc_string_for_domain(domain)
        if dmarc_string is not None:
            return DmarcRecord.from_dmarc_string(dmarc_string)
        else:
            return None


def _extract_tags(dmarc_record):
    dmarc_pattern = "(\w+)=(.*?)(?:; ?|$)"
    return re.findall(dmarc_pattern, dmarc_record)


def _match_dmarc_record(txt_record):
    dmarc_pattern = re.compile('^"?(v=DMARC[^"]*)"?')
    potential_dmarc_match = dmarc_pattern.match(str(txt_record))
    return potential_dmarc_match


def _find_record_from_answers(txt_records):
    dmarc_record = None
    for record in txt_records:
        potential_match = _match_dmarc_record(record)
        if potential_match is not None:
            dmarc_record = potential_match.group(1)
    return dmarc_record


def get_dmarc_string_for_domain(domain):
    try:
        txt_records = dns.resolver.query("_dmarc." + domain, "TXT")
        return _find_record_from_answers(txt_records)
    except dns.resolver.NoAnswer:
        return None
    except TypeError as error:
        logging.exception(error)
        return None