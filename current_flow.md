• End-to-End Detection Flow (actual runtime, no plan docs)

  1. Proxy boots with compiled bundle

  - Proxy startup loads OISP bundle from local registry cache and logs bundle version/counts in crates/soth-proxy/src/transport/proxy_runtime.rs:27.
  - It wires MITM handlers (with_http_handler, with_websocket_handler) in crates/soth-proxy/src/transport/proxy_runtime.rs:262.

  2. First HTTPS touchpoint: CONNECT / client-hello gate

  - Before decrypted HTTP exists, should_intercept decides MITM vs tunnel in crates/soth-proxy/src/transport/proxy.rs:2416.
  - Base CONNECT action comes from host + bundle connect policy (unknown app context) in crates/soth-proxy/src/transport/proxy_routing.rs:238.
  - Then process-aware override happens:
      - resolve socket owner process in crates/soth-proxy/src/process_attribution.rs:53
      - derive bundle id from executable path in crates/soth-proxy/src/process_attribution.rs:152 and crates/soth-proxy/src/transport/proxy_support.rs:596
      - classify app origin (host/non_host) from bundle gating in crates/soth-oisp/src/engine.rs:107
      - evaluate connect policy with host + app identifier + app origin in crates/soth-oisp/src/engine.rs:408
  - Final action can still fail-open to tunnel on FD pressure or learned passthrough in crates/soth-proxy/src/transport/proxy.rs:2524.
  - If intercept=true, TLS MITM proceeds and decrypted requests are visible. If false, traffic remains blind tunnel.

  3. Request ingress classification (after decrypt)

  - Every request enters handle_request in crates/soth-proxy/src/transport/proxy.rs:582.
  - It computes host/path/method, classifies host target (ai/mcp/agent/catalog), and provider hint via resolve_host_target_info in crates/soth-proxy/src/transport/proxy_request.rs:21.
  - It builds body-inspection plan (JSON/post/size/noise/discovery checks) in crates/soth-proxy/src/transport/proxy_request.rs:77.
  - Process attribution is done again for request-level context and decision logging in crates/soth-proxy/src/transport/proxy.rs:757.

  4. Bundle detection (identity and confidence)

  - Detection context is built from host/path/UA/model/process_name/bundle_id in crates/soth-proxy/src/transport/proxy_detection.rs:135.
  - Provider-scoped detection runs via OISP (evaluate_detection) in crates/soth-oisp/src/engine_detection.rs:17.
  - Rule precedence is hardcoded as: model > path > ua > process > env in crates/soth-oisp/src/detection.rs:117.
  - Generic detections (host_classification, unknown, etc.) are normalized to bundle_unclassified and detection_id is cleared in crates/soth-proxy/src/transport/proxy_detection.rs:156.

  5. Request decision and capture contract

  - Request policy decision is evaluated with host/path/method/app_origin in crates/soth-oisp/src/engine.rs:213.
  - Proxy maps decision reason/outcome to step labels in crates/soth-proxy/src/transport/proxy.rs:227.
  - Canonical step constants currently are step0..step4 in crates/soth-core/src/types/exchange.rs:21.
  - Capture policy is derived from detection confidence + reason in crates/soth-proxy/src/transport/proxy_detection.rs:202.
  - Critical enqueue gate: if detection_id is missing, request is forced to metadata-only and not enqueued (should_enqueue_exchange = has_detection) in crates/soth-proxy/src/transport/
    proxy.rs:1260 and crates/soth-proxy/src/transport/proxy.rs:1318.

  6. Pending correlation + spool seed before upstream

  - For trackable requests, proxy stores PendingRequest (exchange_id, decision, detection, headers, etc.) in crates/soth-proxy/src/transport/proxy.rs:1475.
  - It seeds exchange_spool before forwarding in crates/soth-proxy/src/transport/proxy.rs:1834.
  - Spool seed is skipped unless strict detection contract is already resolved (strict detection_id + detection_bundle_version) in crates/soth-proxy/src/transport/proxy_exchange.rs:831.

  7. Response correlation and finalization

  - handle_response pops pending by request id in crates/soth-proxy/src/transport/proxy.rs:1905.
  - It handles JSON/grpc buffered responses and SSE/stream tee capture paths in crates/soth-proxy/src/transport/proxy.rs:2016 and crates/soth-proxy/src/transport/proxy.rs:2049.
  - Non-stream finalization path is in crates/soth-proxy/src/transport/proxy_response.rs:122.
  - Stream and error finalization both call finalize_and_enqueue_exchange in crates/soth-proxy/src/transport/proxy_exchange.rs:453 and crates/soth-proxy/src/transport/proxy_error.rs:64.

  8. Local enqueue to DB

  - Before writing queue row, proxy enforces detection contract again:
      - strict bundle-backed detection_id
      - detection source must be bundle
      - detection bundle version present
      - schema contract validation
        in crates/soth-proxy/src/transport/proxy_exchange.rs:346.
  - If valid, it writes exchange_events + exchange_upload_queue in one transaction via enqueue_exchange_upload_with_blobs at crates/soth-core/src/event_logger_core.rs:285.
  - Spool row is then finalized/deleted (upsert/finalize/delete) in crates/soth-core/src/event_logger_core.rs:121, crates/soth-core/src/event_logger_core.rs:149, crates/soth-core/src/
    event_logger_core.rs:195.

  9. Sync worker upload to cloud

  - Sync loop reads ready queue rows in crates/soth-sync/src/agent.rs:564.
  - It parses payload and validates UUID in crates/soth-sync/src/agent.rs.
  - Converts ExchangeEvent -> ExchangeMetadata in crates/soth-sync/src/agent.rs:1329.
  - Sends gzip batch to `/v1/edge/enroll/exchange` via metadata pusher in crates/soth-sync/src/metadata_pusher.rs.
  - Rejections are classified terminal vs retry; terminal ones are dropped and logged as malformed in crates/soth-sync/src/agent.rs:1546 and crates/soth-sync/src/agent.rs:1026.

  10. Cloud ingest and validation

  - API handler decodes gzip, rate limits, and calls service ingest in ../soth-cloud/crates/soth-cloud-api/src/handlers/exchanges.rs:47.
  - Batch rows are normalized/validated in ../soth-cloud/crates/soth-cloud-api/src/services/exchanges.rs:229 and ../soth-cloud/crates/soth-cloud-api/src/services/exchanges.rs:3626.
  - For schema v1, cloud enforces required detection/device contract (strict detection_id, detection_bundle_version, bundle detection_source for non-collector) in ../soth-cloud/crates/
    soth-cloud-api/src/services/exchanges.rs:3775.
  - Decision contract consistency is enforced in ../soth-cloud/crates/soth-cloud-api/src/services/exchanges.rs:4109.
  - Invalid rows return validation_failed/specific codes; sync then drops or retries based on code class.
