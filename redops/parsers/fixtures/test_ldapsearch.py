"""ldapsearch parser fixtures (D1) — pure parse, no DB.

Proves the three things that matter on an AD engagement: the domain is named,
users become PRINCIPALS (the spray pool), and an anonymous bind that returns
objects is reported as a finding rather than a neutral observation.

Run:  ./venv/bin/python -m redops.parsers.fixtures.test_ldapsearch
"""
import sys

from redops.parsers import ldapsearch as P

ROOTDSE = """\
# extended LDIF
#
# LDAPv3
# base <> with scope baseObject
#

dn:
namingContexts: DC=examplelab,DC=ai
namingContexts: CN=Configuration,DC=examplelab,DC=ai
dnsHostName: DC01.examplelab.ai
defaultNamingContext: DC=examplelab,DC=ai

# search result
search: 2
result: 0 Success
"""

USERS = """\
# Administrator, Users, examplelab.ai
dn: CN=Administrator,CN=Users,DC=examplelab,DC=ai
objectClass: top
objectClass: person
objectClass: user
cn: Administrator
sAMAccountName: Administrator
userPrincipalName: Administrator@examplelab.ai
memberOf: CN=Domain Admins,CN=Users,DC=examplelab,DC=ai

# j.hale, Users, examplelab.ai
dn: CN=j.hale,CN=Users,DC=examplelab,DC=ai
objectClass: user
cn: Jordan Hale
sAMAccountName: j.hale
userPrincipalName: j.hale@examplelab.ai

# Domain Admins, Users, examplelab.ai
dn: CN=Domain Admins,CN=Users,DC=examplelab,DC=ai
objectClass: group
cn: Domain Admins
sAMAccountName: Domain Admins

# DC01, Domain Controllers, examplelab.ai
# REAL AD computer objects also carry person/organizationalPerson/user — the
# first fixture listed only `computer`, which is why machine accounts leaking
# into the principal pool passed the tests.
dn: CN=DC01,OU=Domain Controllers,DC=examplelab,DC=ai
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
objectClass: computer
cn: DC01
sAMAccountName: DC01$
"""


def test_rootdse():
    r = P.to_result(ROOTDSE, host_hint="192.0.2.13")
    names = {e["name"] for e in r.entities}
    assert "examplelab.ai" in names, f"domain not extracted: {names}"
    assert "DC01.examplelab.ai" in names, f"dnsHostName not extracted: {names}"
    assert r.status == "ok", r.status
    print(f"  rootdse: OK — {r.summary}")


def test_users_become_principals():
    r = P.to_result(USERS, host_hint="192.0.2.13")
    names = {e["name"] for e in r.entities}
    assert {"Administrator", "j.hale"} <= names, f"users missing: {names}"
    assert "Domain Admins" in names, "group missing"
    assert "DC01" in names, "computer missing (trailing $ should be stripped)"
    assert r.persist_extra is not None, "users must persist to the principals store"
    assert "2 users" in r.summary, r.summary
    print(f"  users: OK — {r.summary}")


def test_machine_accounts_stay_out_of_the_spray_pool():
    """ABSENCE assertion. DC01$ is objectClass user AND computer; if it lands in
    the principal pool the spray matrix wastes runs on machine accounts and the
    DC never becomes a host node."""
    r = P.to_result(USERS, host_hint="192.0.2.13")
    principals = {e["name"] for e in r.entities if e["type"] == "principal"}
    assert "DC01" not in principals and "DC01$" not in principals, \
        f"machine account leaked into the principal pool: {principals}"
    assert principals == {"Administrator", "j.hale"}, principals
    hosts = {e["name"] for e in r.entities if e["type"] == "host"}
    assert "DC01" in hosts, f"computer should be a host node: {hosts}"
    assert "2 users" in r.summary, r.summary
    print(f"  machine accounts: OK — principals={sorted(principals)}, DC01 is a host")


def test_anonymous_bind_is_a_finding():
    r = P.to_result(USERS, host_hint="192.0.2.13", anonymous=True)
    assert r.findings and "Anonymous LDAP bind" in r.findings[0].title, r.findings
    assert r.findings[0].severity == "high", r.findings[0].severity
    # an authenticated bind returning the same data is NOT a finding
    r2 = P.to_result(USERS, host_hint="192.0.2.13", anonymous=False)
    assert not r2.findings, "authenticated enumeration should not be a finding"
    print("  finding: OK — anonymous bind high; authenticated bind not a finding")


def test_unparseable_yields_no_facts():
    """A wrong `observed` fact is worse than a missing one."""
    r = P.to_result("ldap_bind: Invalid credentials (49)\n")
    assert r.status == "unrecognized", r.status
    assert not r.facts and not r.entities and not r.findings, "unrecognized must carry nothing"
    print("  refusal: OK — unrecognized output produced zero facts")


if __name__ == "__main__":
    n = 0
    for t in (test_rootdse, test_users_become_principals,
              test_machine_accounts_stay_out_of_the_spray_pool,
              test_anonymous_bind_is_a_finding, test_unparseable_yields_no_facts):
        t()
        n += 1
    print(f"\nPASS — {n}/5 ldapsearch cases")
    sys.exit(0)
