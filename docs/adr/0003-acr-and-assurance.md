# ADR 0003: acr values assert the method used, not a legal level

- Status: accepted (architecture recommendation; Q-02 remains open)
- Date: 2026-11-20
- Stories: 2.4, 4.1; architecture ADR-008 "Assurance"

## Decision

- Demo mode always emits `acr=demo` and `eid_env=demo`.
- Production emits `urn:eidbridge:acr:<method>` (for example `urn:eidbridge:acr:smartid`) unless the operator maps the method to another value in `method_acr`. That value states only which verified method was used. It is not an eIDAS level of assurance.
- An operator who maps a method to a level such as `high` takes responsibility for the evidence (agreement, certificate policy, status-check duties under Q-02). The bridge does not infer it from a certificate level label.
- `acr_values` filters the enabled methods to those whose acr equals a requested value. If none remains, the response is `unmet_authentication_requirements`; the bridge never silently downgrades.
- `amr` lists the method name (`smartid`, `mobileid`, `webeid`, `eudi_pid`).
