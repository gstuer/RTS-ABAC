# Server-Aided Access Decision Verification Benchmark

Round-trip time (RTT) estimations that quantify the latency introduced by the optional server-aided access decision
verification of the delegated decision enforcement protocol. The estimations distinguish the verification performed by
the DEP that requests an access decision from the verification performed by the DEP that receives a session
initialization as a next hop, so that the influence of either side on a payload exchange is isolated.

## Experimental Setup

The testbed extends the testbed of the performance analysis by a second PDP, which serves as the verification
authority of both DEPs.

| Device | Address | Role |
| --- | --- | --- |
| Lingonberry | 192.168.0.62 | active entity of the latency estimation |
| Gooseberry | 192.168.0.63 | passive entity of the latency estimation |
| Strawberry | 192.168.0.60 | DEP protecting the active entity |
| Cranberry | 192.168.0.61 | DEP protecting the passive entity |
| Huckleberry | 192.168.0.64 | PDP issuing the session initializations |
| Workstation | 192.168.0.100 | PDP verifying the session initializations |

The policy set, the flow patterns, and the authentication are those of the performance analysis: two granting policies,
one per direction of the message exchange, each a fully specified Ethernet pattern, and an HMAC based on SHA-512. Both
policies are static policies in the sense of Section 3.4.1, so that a non-attribute-related maximum time of validity is
specified and the PDP issues no attribute requests. Both PDPs administer the same policy set, so that they evaluate the
same policies and a deviation would indicate a fault or a compromise rather than a divergence of the policy sets.

A DEP is launched as

    pep.jar -i eth0 -s eth1 --authorization 192.168.0.64 \
            [--decision-verification <incoming> <outgoing>] \
            --authentication localhost --crypto HmacSHA512/256

where `<incoming>` is the verification authority for the session initializations of incoming data frames, i.e. for the
receiving DEP, `<outgoing>` is the verification authority for the session initializations of outgoing data frames, i.e.
for the requesting DEP, and `none` disables the verification for the direction in question. Both DEPs are configured
symmetrically in every run, as the latency estimation measures a round-trip time and therefore traverses both
directions.

The periods of validity, the decision validity offset of a DEP, and the refresh lead time of a PDP are configured as
follows:

| Parameter | Value | Location |
| --- | --- | --- |
| Maximum time of validity, steady-state runs | 2 h | `AuthorizationController` |
| Maximum time of validity, refresh runs | 5 s | `AuthorizationController` |
| Decision validity offset of a DEP | 100 ms | `AuthorizationManager` |
| Refresh lead time of a PDP (`SLEEP_OFFSET`) | 300 ms | `PolicyEvaluator` |
| Refresh threshold of a PDP (`REFRESH_THRESHOLD`) | 350 ms | `PolicyEvaluator` |

A PDP replaces a cached access decision once the period of validity of its predecessor has 300 ms left, whereas a DEP
repeats the access request once its own copy has 100 ms left. The resulting margin of 200 ms ensures that a DEP
receives a newly derived access decision rather than the expiring one. Were the two values equal, a DEP would repeat
the access request at the instant at which the PDP derives the successor, and it would repeat the request until the
derivation completes. The refresh threshold must exceed the refresh lead time, as the periodic evaluation would
otherwise not derive a successor after it has waited for it.

The refresh runs are preceded by a period that exceeds the period of validity, so that the access decisions of both
directions have expired when the measurement starts and the first measured exchange comprises the access request and
the session initialization of both directions. This is the only exchange of a refresh run in which the verification of
a receiving DEP lies on the critical path, as a receiving DEP otherwise still holds the predecessor of the access
decision it verifies.

Each run is preceded by three discarded estimations of 5000 readings, with the DEPs and the PDPs left running in
between, so that the reported estimations are measured in a warm state. Every run restarts all four components, as a
PDP caches the key of a DEP for the lifetime of its process while the HMAC authenticator derives a key per process:
restarting a DEP alone leaves the PDP with a key that no longer verifies, after which it discards the access requests
of that DEP without notice. The access decisions of both directions are installed immediately before an estimation
starts, as the first data frame of a direction is dropped while a receiving DEP verifies and the estimation harness
tolerates the loss of a single initialization packet only.

## Runs

| Run | Maximum time of validity | Verification | File |
| --- | --- | --- | --- |
| 1 | 2 h | none | `rtt_steady_noverification.json` |
| 2 | 2 h | requesting and receiving DEP | `rtt_steady_verification_both.json` |
| 3 | 5 s | none | `rtt_refresh_noverification.json` |
| 4 | 5 s | receiving DEP | `rtt_refresh_verification_receiver.json` |
| 5 | 5 s | requesting DEP | `rtt_refresh_verification_sender.json` |
| 6 | 5 s | requesting and receiving DEP | `rtt_refresh_verification_both.json` |

Every run comprises 100000 readings. The `pdp_verifier_*.log` files are the standard output of the verifying PDP. Each
`[PDP] Verify ... (took N µs)` line is one answered verification request and reports its service time. The logs of the
runs without verification contain no such line, which confirms that the verifying PDP is not involved when the
verification is disabled. The `pdp_issuer_run3_refresh_noverification.log` file is the standard output of the issuing
PDP of run 3; each `[PDP] Grant ... (took N µs)` line is one answered access request and reports its service time.

## Results

All times are given in milliseconds. A refresh event is a group of consecutive readings that exceeds three times the
median of its run, where readings less than one second apart belong to the same event.

### Steady State

| Run | Verification | n | Lost | $\widetilde{x}$ | $\bar{x}$ | $s$ | p99 | <= 6 ms | <= 40 ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | none | 100000 | 0 | 2.126 | 2.141 | 0.123 | 2.926 | 99.997 % | 100.000 % |
| 2 | both | 100000 | 0 | 2.106 | 2.106 | 0.215 | 2.843 | 99.991 % | 100.000 % |

No access request, no session initialization, and no verification occurred during either run, as the maximum time of
validity exceeds the duration of a run by far. The verification therefore does not influence the steady state of a
payload exchange, which is the expected result: a verification is performed once per session initialization and not
per data frame.

### Decision Refresh

| Run | Verification | n | Lost | $\widetilde{x}$ | $\bar{x}$ | $s$ | p99 | <= 6 ms | <= 40 ms |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 3 | none | 100000 | 0 | 2.271 | 2.272 | 0.268 | 2.964 | 99.893 % | 100.000 % |
| 4 | receiving DEP | 99997 | 3 | 2.322 | 2.320 | 0.310 | 3.019 | 99.885 % | 100.000 % |
| 5 | requesting DEP | 100000 | 0 | 2.295 | 2.307 | 0.547 | 3.036 | 99.890 % | 99.999 % |
| 6 | both | 100000 | 0 | 2.287 | 2.279 | 0.576 | 3.016 | 99.887 % | 99.998 % |

Peak of a refresh event, and the first measured exchange, in which the access decisions of both directions are acquired:

| Run | Verification | Events | $\bar{x}$ | $\widetilde{x}$ | $s$ | Min | Max | First exchange |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 3 | none | 52 | 9.24 | 8.67 | 1.79 | 7.24 | 15.92 | 20.21 |
| 4 | receiving DEP | 55 | 10.39 | 8.82 | 4.77 | 7.02 | 38.43 | three data frames dropped |
| 5 | requesting DEP | 51 | 19.29 | 19.31 | 3.66 | 8.34 | 26.77 | 43.72 |
| 6 | both | 51 | 20.15 | 18.11 | 5.88 | 12.89 | 40.10 | 48.76 |

The period of a refresh event is 4.60 s to 4.66 s in all four runs, which corresponds to the maximum time of validity
reduced by the refresh lead time of the PDP. Each direction is refreshed by the DEP that sends its data frames, so that
a run comprises approximately 51 refreshes per direction. As the two periods of validity end at nearly the same time,
both refreshes fall into the same measured exchange, which is the worst case of a bidirectional message exchange.

1. The verification of a receiving DEP influences neither the steady state nor a refresh. The peak of a refresh event
   of run 4 equals the peak of run 3, as a receiving DEP still holds the predecessor of the access decision it verifies
   and therefore enforces data frames while the verification is in progress. Its cost becomes observable only when no
   predecessor is available: run 4 is the only run that lost data frames, three of 100000, whereas its peak of a
   refresh event equals that of run 3. The loss is therefore attributable to the first measured exchange rather than to
   a refresh, as a loss at a refresh would recur at each of the approximately 51 refreshes per direction. The
   estimation harness does not record the position of a lost reading, so that the first exchange of run 4 is reported
   as a loss rather than as a latency.
2. The verification of a requesting DEP adds 10.6 ms to the peak of a refresh event, from 8.67 ms to 19.31 ms. A
   requesting DEP buffers the data frame that triggered the access request and forwards it once the access decision is
   available, so that it does not acquire a successor ahead of time but at the moment at which its predecessor
   expires, and the verification lies on the critical path of that data frame.
3. The verification of both DEPs is not more expensive than the verification of the requesting DEP alone, 18.11 ms
   against 19.31 ms, which confirms that the verification of a receiving DEP is performed concurrently and within the
   remaining period of validity of its predecessor. The first measured exchange, however, grows from 43.72 ms to
   48.76 ms, as the verification of the receiving DEP lies on the critical path when no predecessor is available.
4. A verified session initialization costs no data frame once a predecessor exists. No session initialization was
   discarded as unverifiable in any run, and no reading of the runs 3, 5, and 6 was lost. The decision validity offset
   of 100 ms therefore covers the verification of both DEPs. A single data frame was recorded as unauthorized by the
   receiving DEP of run 6 without affecting a measured exchange. The record does not distinguish an incoming from an
   outgoing data frame, and the background traffic of a protected entity produces the same record, as run 2 shows, in
   which no refresh occurred at all.
5. The number of exchanges that exceed the RTT bound of 6 ms for the IEC 61850 message types 1A and 4 is determined by
   the number of refreshes rather than by the verification, 0.107 % to 0.115 % in all four refresh runs. The
   verification shifts individual exchanges beyond the bound of 40 ms for message type 1B, two of 100000 exchanges in
   run 6 and one in run 5, whereas all exchanges of the runs without verification and of the steady-state runs remain
   within it.

Service time of a verification request at the verifying PDP, excluding the first request of a DEP, which additionally
comprises a key exchange with that DEP and took 23 ms to 82 ms:

| Run | n | $\widetilde{x}$ | $\bar{x}$ | Min | Max |
| --- | --- | --- | --- | --- | --- |
| 2 | 3 | 2515 µs | 2099 µs | 795 µs | 2987 µs |
| 4 | 122 | 1191 µs | 1257 µs | 337 µs | 4182 µs |
| 5 | 121 | 1223 µs | 1287 µs | 337 µs | 2708 µs |
| 6 | 243 | 1023 µs | 1077 µs | 175 µs | 3009 µs |

Service time of an access request at the issuing PDP, measured over run 3 and excluding the first request of a DEP:

| Run | n | $\widetilde{x}$ | $\bar{x}$ | Min | Max |
| --- | --- | --- | --- | --- | --- |
| 3 | 118 | 694 µs | 797 µs | 517 µs | 2047 µs |

An access request thus occupies the issuing PDP for 694 µs, which corresponds to approximately 1440 session
initializations per second if they were served sequentially. The implementation serves requests concurrently, so that
the figure is a conservative one; the saturation of a PDP is not measured.

The verifying PDP answered 209 verification requests in run 6 against the 105 access requests of the two DEPs, i.e.
each DEP verifies the session initialization of the direction it sends and the session initialization of the direction
it receives. In run 4 and in run 5 it answered one request per access request, as only one of the two is verified. The
number of session initializations equals the number of access requests in every run, which confirms that a DEP repeats
an access request once per refresh and not repeatedly.

## Limitations

The verifying PDP is a workstation, whereas the issuing PDP is a Raspberry Pi 5, so that the two service times are not
directly comparable. The verification is measured as an additional message exchange within the same local network,
which is the overhead the verification adds; the situation that motivates it, a session initialization issued by a PDP
of a remote SAS, is not reproduced.

The steady state of the refresh runs is not directly comparable to the steady state of the steady-state runs. A DEP
retains the expired predecessors of its access decisions and evaluates the decision enforcement function for every
access decision it holds, so that the median of a refresh run grows by 0.151 ms (run 3) to 0.203 ms (run 6) from its
first to its last quarter, whereas the median of run 1 is constant within 0.011 ms. The comparison of the runs 3 to 6
is unaffected, as all four accumulate access decisions at the same rate.

Both PDPs administer the same policy set, so that the runs exercise the verification of a session initialization that
the verifying PDP authorizes. The rejection of a session initialization that it does not authorize is not covered by
these runs.
