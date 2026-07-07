#! VULNERABLE sso-group-map — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant mapGroup confidence 70

let raw = fetch<web>
privileged { mapGroup(raw) }  # tainted -> tool: REJECTED
