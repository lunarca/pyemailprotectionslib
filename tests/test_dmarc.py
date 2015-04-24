import emailprotectionslib.dmarc as dmarclib


def test_find_record_from_answers_valid():
    dmarc_string = ("v=DMARC1; p=quarantine; rua=mailto:"
                    "mailauth-reports@google.com")
    txt_records = [dmarc_string, "asdf", "not dmarc"]

    assert dmarclib._find_record_from_answers(txt_records) == dmarc_string


def test_find_record_from_answers_invalid():
    txt_records = ["asdf", "another", "yetanother"]

    assert dmarclib._find_record_from_answers(txt_records) is None


def test_match_dmarc_record():
    valid_dmarc_string = ("v=DMARC1; p=quarantine; rua=mailto:"
                          "mailauth-reports@google.com")
    assert dmarclib._match_dmarc_record(valid_dmarc_string) is not None


def test_match_dmarc_record_invalid():
    invalid_dmarc = ("vMARC1; p=quarantine; rua=mailto:"
                     "mailauth-reports@google.com")
    assert dmarclib._match_dmarc_record(invalid_dmarc) is None


def test_extract_tags_pass():
    dmarc_string = ("v=DMARC1; p=quarantine; rua=mailto:"
                    "mailauth-reports@google.com")
    dmarc_tags = [("v", "DMARC1"), ("p", "quarantine"),
                  ("rua", "mailto:mailauth-reports@google.com")]
    assert dmarclib._extract_tags(dmarc_string) == dmarc_tags


def test_from_dmarc_record_pass():
    dmarc_string = "v=DMARC1; p=quarantine"
    dmarc_record = dmarclib.DmarcRecord()
    dmarc_record.version = "DMARC1"
    dmarc_record.policy = "quarantine"
    dmarc_record.record = dmarc_string
    assert dmarclib.DmarcRecord.from_dmarc_string(dmarc_string) == dmarc_record