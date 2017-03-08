import emailprotectionslib.dmarc as dmarclib


def test_find_record_from_answers_valid():
    dmarc_string = '"v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com"'
    dmarc_string_without_quotes = 'v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com'
    txt_records = [("google.com", "txt", dmarc_string),
                   ("google.com", "txt", "asdf"),
                   ("google.com", "txt", "not dmarc")]

    assert dmarclib._find_record_from_answers(txt_records) == dmarc_string_without_quotes


def test_find_record_from_answers_invalid():
    txt_records = ["asdf", "another", "yetanother"]

    assert dmarclib._find_record_from_answers(txt_records) is None


def test_match_dmarc_record():
    valid_dmarc_string = ('"v=DMARC1; p=quarantine; rua=mailto:'
                          'mailauth-reports@google.com"')

    assert dmarclib._match_dmarc_record(valid_dmarc_string) is not None


def test_match_dmarc_record_invalid():
    invalid_dmarc = ('"vMARC1; p=quarantine; rua=mailto:'
                     'mailauth-reports@google.com"')
    assert dmarclib._match_dmarc_record(invalid_dmarc) is None


def test_extract_tags_pass():
    dmarc_string = ("v=DMARC1; p=quarantine; rua=mailto:"
                    "mailauth-reports@google.com")
    dmarc_tags = [("v", "DMARC1"), ("p", "quarantine"),
                  ("rua", "mailto:mailauth-reports@google.com")]
    assert dmarclib._extract_tags(dmarc_string) == dmarc_tags


def test_from_dmarc_record_pass():
    dmarc_string = "v=DMARC1; p=quarantine"
    dmarc_record = dmarclib.DmarcRecord("google.com")
    dmarc_record.version = "DMARC1"
    dmarc_record.policy = "quarantine"
    dmarc_record.domain = "google.com"
    dmarc_record.record = dmarc_string
    assert dmarclib.DmarcRecord.from_dmarc_string(dmarc_string, "google.com") == dmarc_record


def test_from_domain_pass():
    assert dmarclib.DmarcRecord.from_domain("google.com") is not None


def test_record_strength_quarantine():
    dmarc_string = ("v=DMARC1; p=quarantine; rua=mailto:"
                          "mailauth-reports@google.com")
    record = dmarclib.DmarcRecord.from_dmarc_string(dmarc_string, "google.com")

    assert record.is_record_strong() is True


def test_record_strength_none():
    dmarc_string = ("v=DMARC1; p=none; rua=mailto:"
                          "mailauth-reports@google.com")
    record = dmarclib.DmarcRecord.from_dmarc_string(dmarc_string ,"google.com")

    assert record.is_record_strong() is False


def test_record_strength_reject():
    dmarc_string = ("v=DMARC1; p=reject; rua=mailto:"
                          "mailauth-reports@google.com")
    record = dmarclib.DmarcRecord.from_dmarc_string(dmarc_string, "google.com")

    assert record.is_record_strong() is True


def test_record_strength_no_policy():
    dmarc_string = ("v=DMARC1; rua=mailto:"
                          "mailauth-reports@google.com")
    record = dmarclib.DmarcRecord.from_dmarc_string(dmarc_string, "google.com")

    assert record.is_record_strong() is False
