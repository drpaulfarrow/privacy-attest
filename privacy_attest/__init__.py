"""privacy-attest: a member-run privacy review agent that produces signed attestations.

Members run it against their own code, across one repository or many. The reviewer
receives answers, override reasons, the member's repository inventory and
cryptographic fingerprints of the evidence, never the code.
"""
__version__ = "0.2.0"
AGENT_NAME = "privacy-attest"
PREDICATE_TYPE = "https://github.com/drpaulfarrow/privacy-attest/attestation/privacy-review/v0.2"
FRAGMENT_TYPE = "https://github.com/drpaulfarrow/privacy-attest/attestation/privacy-review-fragment/v0.2"
REVEAL_TYPE = "https://github.com/drpaulfarrow/privacy-attest/attestation/spot-check-reveal/v0.2"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
