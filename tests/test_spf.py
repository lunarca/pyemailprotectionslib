import emailprotectionslib.spf as spflib


def test_find_record_from_answers_valid():
    spf_string = "v=spf1 include:_spf.google.com ~all"
    txt_records = [spf_string, "asdf", "not dmarc"]

    assert spflib._find_record_from_answers(txt_records) == spf_string


def test_find_record_from_answers_invalid():
    txt_records = ["asdf", "another", "yetanother"]

    assert spflib._find_record_from_answers(txt_records) is None


def test_match_spf_record():
    valid_spf_string = "v=spf1 include:_spf.google.com ~all"
    assert spflib._match_spf_record(valid_spf_string) is not None


def test_match_spf_record_invalid():
    invalid_spf = "vsf1 include:_spf.google.com ~all"
    assert spflib._match_spf_record(invalid_spf) is None


def test_extract_all_mechanism():
    mechanisms = ["a", "mx", "~all"]
    assert str(spflib._extract_all_mechanism(mechanisms)) == "~all"


def test_extract_version():
    spf_string = "v=spf1 include:_spf.google.com ~all"
    assert spflib._extract_version(spf_string) == "spf1"


def test_extract_mechanisms():
    spf_string = "v=spf1 include:_spf.google.com mx ~all"
    mechanisms = ["include:_spf.google.com", "mx", "~all"]
    assert spflib._extract_mechanisms(spf_string) == mechanisms


def test_from_spf_string():
    spf_string = "v=spf1 include:_spf.google.com mx ~all"
    spf_record = spflib.SpfRecord()
    spf_record.all_string = "~all"
    spf_record.version = "spf1"
    spf_record.record = spf_string
    spf_record.mechanisms = ["include:_spf.google.com",
                             "mx",
                             "~all",
                             ]
    assert spflib.SpfRecord.from_spf_string(spf_string) == \
        spf_record


def test_get_redirect_domain():
    spf_string = "v=spf1 redirect:_spf.google.com"
    spf_record = spflib.SpfRecord.from_spf_string(spf_string)
    assert spf_record.get_redirect_domain() == "_spf.google.com"