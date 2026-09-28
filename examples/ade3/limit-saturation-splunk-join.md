# ADE3-06 Example: Limit Saturation - Rundll32 with No Command Line Arguments with Network

**Bug Category:** ADE3-06 Context Development - Limit Saturation

## Original Rule

**Source:** [Splunk ESCU - Rundll32 with no Command Line Arguments with Network](https://github.com/splunk/security_content/blob/develop/detections/endpoint/rundll32_with_no_command_line_arguments_with_network.yml) (version 16, status: production)

**Description:** Detects the execution of rundll32.exe without command line arguments, followed by a network connection. rundll32.exe typically requires arguments to function, and its absence is often associated with malicious activity such as Cobalt Strike.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  FROM datamodel=Endpoint.Processes
  WHERE `process_rundll32` Processes.process IN ("*rundll32", "*rundll32.exe", "*rundll32.exe\"")
  BY host _time span=1h Processes.action Processes.dest ... Processes.process_id ...
| `drop_dm_object_name(Processes)`
| rename dest as src
| join host process_id
  [
    | tstats `security_content_summariesonly` count
      FROM datamodel=Network_Traffic.All_Traffic
      WHERE All_Traffic.dest_port != 0
      BY host All_Traffic.action All_Traffic.app All_Traffic.bytes All_Traffic.bytes_in All_Traffic.bytes_out
         All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.dvc All_Traffic.protocol
         All_Traffic.protocol_version All_Traffic.src All_Traffic.src_ip All_Traffic.src_port
         All_Traffic.transport All_Traffic.user All_Traffic.vendor_product All_Traffic.direction
         All_Traffic.process_id
    | `drop_dm_object_name(All_Traffic)`
  ]
| `rundll32_with_no_command_line_arguments_with_network_filter`
```

(Process-side `BY` list abbreviated for space; the subsearch is shown in full.)

## The Bug

**Detection relies on:** A `join` whose right side (the subsearch) is expected to return the network connection made by the flagged rundll32 process.

**Implicit assumption:** The subsearch returns every network connection relevant to the join key within the search window.

**Reality:** Splunk's `join` documentation states plainly: *"A maximum of 50,000 rows in the right-side dataset can be joined with the left-side dataset over a maximum runtime of 60 seconds."* These are the `subsearch_maxout` and `subsearch_maxtime` settings in `limits.conf`.

The subsearch's only filter is `All_Traffic.dest_port != 0`, which matches nearly every network flow, and it groups by 20 fields — including `bytes`, `src_port`, and `dest_port` — that are close to unique per connection. So the subsearch materializes roughly one row per network flow across the monitored estate, competing for the same 50,000-row budget regardless of how many of those flows involve rundll32.

## The Bug in Practice

**No attacker action required.** In any environment recording more than 50,000 qualifying flows within the search window — a routine volume for a mid-size or larger estate — the subsearch truncates. Splunk returns a partial result set with a warning banner; the scheduled search itself does not fail or alert on the truncation.

Whether the specific row the rule needs — the connection from the flagged rundll32 process — survives the cut depends on where in the (unordered, from the rule's perspective) result set it happens to fall. There is no guarantee it is retained. If it is dropped, the process-side row from the left side of the `join` (which defaults to `type=inner`) has no matching network row, and the event is silently excluded from the final result table.

**Volume can also be shaped, not just grown.** Because the subsearch's budget is spent on every flow in the datamodel and not narrowed toward rundll32 activity specifically, anything that inflates overall `Network_Traffic.All_Traffic` volume within the search window — a scan, a backup job, a burst of legitimate outbound connections — competes for the same 50,000 rows and increases the odds that the one row the rule needs is the one that gets cut.

## Detection Logic Analysis

**Process-side row (retained):** `tstats` over `Endpoint.Processes` is not subject to the join's subsearch cap — it streams. The flagged rundll32 execution appears here regardless of estate size.

**Subsearch row (at risk):** The corresponding network connection depends on where it falls within the capped 50,000-row, 60-second window of `Network_Traffic.All_Traffic` activity across the entire environment for that period.

**Result:** `join host process_id [...]` with default `type=inner` finds no match for the process-side row whenever its corresponding network row was excluded by truncation. The event that should have alerted never reaches `rundll32_with_no_command_line_arguments_with_network_filter`. **False Negative** — with no error, no alert, and no signal to the analyst that anything was dropped.

## Why This Is Context Development

**Context Development:** The primary in-scope action — rundll32 executing with no arguments and making a network connection — is unchanged. What determines detection is the surrounding data volume on the other side of the `join`, which the rule's author did not shape toward the records that matter.

Unlike ADE3-01/02/03/05, no preparatory step by the attacker is required for this bug to produce False Negatives — it activates as soon as the environment's flow volume exceeds the engine's default cap. It becomes actively exploitable if an attacker can also drive up ordinary, unrelated network volume within the search window, since that volume competes for the same fixed budget as the malicious connection.

## Fix

Per [Mitigation 4](../../docs/mitigations/README.md#mitigation-4-keep-bounded-operators-on-the-rare-side): invert the correlation so the bounded operator holds the **rare** set. The subsearch returns only the rundll32-with-no-arguments processes, and the high-volume `Network_Traffic` data model is the streamed, unbounded side, filtered by the subsearch's output —

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  FROM datamodel=Network_Traffic.All_Traffic
  WHERE All_Traffic.dest_port != 0
    [ | tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes
        WHERE `process_rundll32` Processes.process IN ("*rundll32", "*rundll32.exe", "*rundll32.exe\"")
        BY host Processes.process_id
      | rename Processes.process_id AS All_Traffic.process_id
      | fields host All_Traffic.process_id ]
  BY host All_Traffic.process_id All_Traffic.dest All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
```

The subsearch is still bounded (10,000 results by default), but it now holds the records the rule is about. If the estate has more than 10,000 rundll32-with-no-arguments processes in one window, the rule has a false-positive problem to solve first. The same subsearch-in-`WHERE` pattern is used by production ESCU detections such as *Attacker Tools On Endpoint* and *Prohibited Network Traffic Allowed*. The trade-off: the output carries network fields only, so pull process context (parent, user, path) from `Endpoint.Processes` during triage or in a follow-up enrichment step.

## Impact

**False Negative:** A rundll32 process with no command-line arguments making a network connection — the exact pattern the rule targets — is not detected, whenever the estate's overall connection volume for the search window exceeds Splunk's default subsearch cap.

**Scope preservation:** The activity is still "rundll32 with no arguments, connecting out" — it is in scope, but the detection logic's use of `join` fails to surface it once volume grows past the operator's limit.

---

**Related Documentation:**
- [ADE3 Context Development](../../docs/taxonomy/ade3-context-development.md#ade3-06-context-development---limit-saturation)
- [Detection Logic Bug Theory](../../docs/theory/detection-logic-bugs.md)
- [Mitigations - Limit Saturation](../../docs/mitigations/README.md#mitigation-4-keep-bounded-operators-on-the-rare-side)

**Other ADE3-06 Examples (linked directly to source, no dedicated write-up yet):**
- [Windows WinLogon with Public Network Connection](https://github.com/splunk/security_content/blob/develop/detections/endpoint/windows_winlogon_with_public_network_connection.yml)
- [Log4Shell JNDI Payload Injection with Outbound Connection](https://github.com/splunk/security_content/blob/develop/detections/web/log4shell_jndi_payload_injection_with_outbound_connection.yml)
- [Hunt PDB File Paths in Reflective .NET Module Loads](https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Hunt%20PBD%20File%20Paths%20in%20Reflective%20.net%20Module%20Loads.md)
- [Process Events - Identify Low Port Bindings](https://github.com/CrowdStrike/logscale-community-content/blob/main/Log-Sources/CrowdStrike/FLTR/crowdstrike-fltrcore/src/queries/ProcessEvents-IdentifyLowPortBindings.yaml)
