#! SSO group mapping — untrusted an assertion can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires mapGroup — the sso group mapping sink
#! @effect io
#! @confidence 70
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant mapGroup confidence 70

type IdpGroup = Staff | Admins | Guests
type Decision = Map(IdpGroup) | Deny

let raw = fetch<web>  # UNTRUSTED an assertion — tainted
quarantined { let d = extract<Decision>(raw) confidence 70 }  # only a fixed Decision (payloads too) crosses
privileged { mapGroup(d) }  # act on the trusted decision only
