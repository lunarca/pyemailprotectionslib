# `pyemailprotectionslib`

This is a simple library designed to assist people with finding email protections.

## Usage

The simplest use of this library is to find and process SPF and DMARC records for domains. This is easiest with the `SpfRecord.from_domain(domain)` and `DmarcRecord.from_domain(domain)` factory methods.

Example:

    import emailprotectionslib.spf as spf
    import emailprotectionslib.dmarc as dmarc
    
    spf_record = spf.SpfRecord.from_domain("google.com")
    dmarc_record = dmarc.DmarcRecord.from_domain("google.com")
    
    print spf_record.record
    print dmarc_record.policy