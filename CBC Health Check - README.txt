The Carbon Black Health Check generates a detailed technical deck of findings and recommendations, and a less extensive executive deck. 
Both of which can be provided to the customer after a presentation of the results. The health check authenticates to Carbon Black Cloud 
using API credentials, so it all takes place remotely (see below for instructs on obtaining the API credentials).

The health check provides data in the following areas:
    tenant/org metadata
    device inventory summary
    alert summary (30 days)
    policy and rule posture
    watchlist coverage
    policy drift from previous run baseline
    policy settings posture
    core prevention mode posture (monitor vs block)
    alert workflow and closure aging
    alert analysis
    API and connector usage hygiene
    permission rule audit
    banned hash age review
    endpoint state distribution
    daily alert and threat score trends
    dormant user login detection
    sensor coverage quality (stale and unassigned)
    alert quality (noise, repeats, unresolved aging)
    policy efficacy by group (combined standard and core prevention posture)
    policy tuning analysis (Broadcom Good/Better/Best maturity mapping)
    Writes outputs to JSON and CSV for easy sharing.
    Writes a PowerPoint executive summary from summary.json for stakeholder sharing.
    Writes a second technical PowerPoint deck from summary.json for engineering review.

Required API Key from the customer:
Use the built-in "Super Admin" role when creating the API key in Settings → API Access.

Several checks depend on the CBC Access v2 grants API (GET /access/v2/orgs/{org}/grants/{principal}) to resolve user roles and API 
connector access level types. This endpoint is only accessible to Super Admin credentials. The "View All" built-in role and all 
custom access levels return 403 for connector principal lookups (psc:cnn:*), even though they can read user principal grants. 
The relevant permission is not exposed as a configurable capability in the Access Levels UI, so there is no way to grant it to a restricted key.

If a non-Super Admin key is used, the tool will still run and produce output, but with these gaps (verified with a View All-style key):

    Org details (GET /appservices/v5/orgs/{org_id}) returns 403 and is recorded as an org check failed error. As a result:
    The cover slide and deck filenames fall back to the backend hostname instead of the org domain.
    EEDR-only detection (ORG_DISABLE_DEFENSE_RULES) cannot run, so policy and core prevention slides render charts instead of "not applicable" on EEDR-only tenants.
    Users API (GET /appservices/v6/orgs/{org_key}/users) returns 403. User and login data still comes from audit logs, but user roles show as unknown.
