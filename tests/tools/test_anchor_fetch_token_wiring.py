"""#951 (slice 1): the ESP arm of fetchToken allocates nothing of its own and holds _mutex only for
the state copy and the install. The pieces it calls are host-compiled and pinned by
FetchTokenOwnCode_test.cpp (the request builder, the lifetime decode, the bearer assignment, the
WebSocket header, the too-big refusal, the failure witness). The anchor client compiles only on the
device, so no host test reaches fetchToken itself; this pins what it may and may not contain."""
import os
import re
import unittest

SIP = os.path.join(os.path.dirname(__file__), "..", "..", "src", "SIP")


def body_of(src, signature):
    start = src.rindex(signature)  # the last definition: the ESP arm, not a host stub
    brace = src.index("{", start)
    depth = 0
    for i in range(brace, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[brace:i + 1]
    raise AssertionError("unbalanced body for " + signature)


def code_only(text):
    return "\n".join(line.split("//")[0] for line in text.split("\n"))


def read(name):
    with open(os.path.join(SIP, name), encoding="utf-8") as f:
        return code_only(f.read())


def no_strings(text):
    """Log text is not code: "a new token" must not read as an allocation."""
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', text)


LOCK = re.compile(r"std::lock_guard<std::mutex>\s+\w+\(_mutex\);")


def lock_scopes(body):
    """The text from each _mutex guard to the end of the block that holds it."""
    scopes = []
    for m in LOCK.finditer(body):
        depth = 0
        for i in range(m.end(), len(body)):
            if body[i] == "{":
                depth += 1
            elif body[i] == "}":
                if depth == 0:
                    scopes.append(body[m.start():i])
                    break
                depth -= 1
        else:
            raise AssertionError("a _mutex guard in fetchToken has no end")
    return scopes


# What takes the heap, or the time, or both. A lock must not hold any of it.
SLOW = re.compile(r"esp_http_client_\w+\s*\(|esp_websocket_client_\w+\s*\(|makeAuthedClient\s*\(|"
                  r"readJsonStringField\s*\(|acceptLifetime\s*\(|tokenLifetimeUs\s*\(|haveCachedToken\s*\(|vTaskDelay|claimWaiting\s*\(|"
                  r"std::string\b(?!_view)|std::vector|urlEncode\s*\(|to_string|\bnew\b|make_unique|make_shared")
# Own-code heap in fetchToken: no string, no vector, no encode-to-string, no allocation at all.
HEAP = re.compile(r"std::string\b(?!_view)|std::vector|urlEncode\s*\(|std::to_string|\bnew\b|make_unique|make_shared|"
                  r"\bmalloc\s*\(|\bstrdup\s*\(|\.assign\s*\(|\.append\s*\(|\bstd::ostringstream|\bsnprintf\s*\(")


class FetchTokenWiringTest(unittest.TestCase):
    longMessage = False  # a failure prints its reason, not the whole function

    def setUp(self):
        self.cpp = read("TelephonyAnchorClient.cpp")
        self.fetch = body_of(self.cpp, "bool TelephonyAnchorClient::fetchToken(")
        self.init = body_of(self.cpp, "bool TelephonyAnchorClient::init(")

    def test_fetchToken_names_no_string_vector_or_allocation_of_its_own(self):
        code = no_strings(self.fetch)
        hit = HEAP.search(code)
        self.assertIsNone(hit, "fetchToken allocates on its own: %r" % (hit and code[hit.start() - 40:hit.end() + 40]))

    def test_the_mutex_is_held_for_the_state_copy_and_the_install_and_nothing_slower(self):
        scopes = lock_scopes(self.fetch)
        self.assertEqual(len(scopes), 2, "the request copy and the install, no third scope")
        for scope in scopes:
            hit = SLOW.search(no_strings(scope))
            self.assertIsNone(hit, "a slow or allocating call under _mutex: %r" % (hit and scope[hit.start():hit.end() + 30]))
        self.assertIn("buildTokenRequest(", scopes[0], "the copy out of the members is the first scope")
        self.assertIn("installIfNewer(", scopes[1], "the install is the second")

    def test_no_socket_call_sits_between_a_lock_and_its_release(self):
        # The same rule, from the other side: every esp_http_client_* call (open, write, headers,
        # read via readJsonStringField, close) is outside every _mutex scope.
        for call in ("esp_http_client_open(", "esp_http_client_write(", "esp_http_client_fetch_headers(",
                     "readJsonStringField(", "esp_http_client_close(", "esp_http_client_cleanup("):
            at = self.fetch.index(call)
            for scope in lock_scopes(self.fetch):
                start = self.fetch.index(scope)
                self.assertFalse(start <= at < start + len(scope), call + " is inside a _mutex scope")

    def test_the_lifetime_is_resolved_before_the_lock_and_the_cache_is_asked_only_outside_it(self):
        accept = self.fetch.index("acceptLifetime(lease, tokenStr, [this] { return haveCachedToken(); }, lifetimeUs)")
        gate = self.fetch.index("installed = _tokenGate.installIfNewer(issuedUs);")
        lock = self.fetch.rindex("std::lock_guard<std::mutex> lock(_mutex);", 0, gate)
        self.assertLess(accept, lock, "the decode is CPU work and takes its scratch from the arena, outside the lock")
        self.assertLess(self.fetch.index("acceptToken(tokenStr)"), accept)
        for scope in lock_scopes(self.fetch):
            self.assertNotIn("haveCachedToken", scope, "haveCachedToken() takes _mutex itself")
        helper = " ".join(body_of(self.cpp, "static bool acceptLifetime(").split())   # one line: the call wraps
        self.assertIn("lease.spare(), lease.spareBytes()", helper, "the scratch is the arena's unused tail")
        self.assertIn("std::string_view(lease.data(), lease.size())", helper, "expires_in is read from the whole response")
        self.assertIn("return lifetimeUs != 0;", helper, "a lifetime of 0 is the refusal: the token is not installed")
        self.assertEqual(self.fetch.count("acceptLifetime("), 1)

    def test_a_token_whose_lifetime_is_refused_is_not_installed_and_the_cached_one_stays(self):
        # acceptLifetime() false short-circuits the whole install block: success stays false, so the
        # end of fetchToken leaves token_fetch_failed_951 and returns false, and _bearerHeader and
        # the stamp are untouched because the gate is inside the block.
        cond = self.fetch[self.fetch.index("int64_t lifetimeUs = 0;"):self.fetch.index("installed = _tokenGate.installIfNewer")]
        self.assertRegex(cond, r"(?s)readJsonStringField\(.*?&&\s*acceptToken\(tokenStr\)\s*&&\s*acceptLifetime\(")
        self.assertEqual(self.fetch.count("success = true;"), 1)
        self.assertGreater(self.fetch.index("success = true;"), self.fetch.index("installed = _tokenGate.installIfNewer"))

    def test_a_token_that_does_not_fit_is_refused_before_the_gate_advances(self):
        accept = self.fetch.index("acceptToken(tokenStr)")
        gate = self.fetch.index("installed = _tokenGate.installIfNewer(issuedUs);")
        self.assertLess(accept, gate, "checkToken (which refuses a too-big token) runs before the stamp can move")
        logic = read("TelephonyAnchorLogic.hpp")
        check = body_of(logic, "inline TokenCheck checkToken(")
        self.assertIn("kMaxTokenBytes", check)
        self.assertIn("TokenCheck::TooBig", check)

    def test_the_websocket_header_is_built_in_the_arena_after_the_lock_is_released(self):
        gate = self.fetch.index("installed = _tokenGate.installIfNewer(issuedUs);")
        ws = self.fetch.index("telephony::wsAuthHeaderInPlace(")
        setter = self.fetch.index("esp_websocket_client_set_headers(")
        self.assertLess(gate, ws)
        self.assertLess(ws, setter)
        for scope in lock_scopes(self.fetch):
            self.assertNotIn("wsAuthHeaderInPlace", scope)
            self.assertNotIn("set_headers", scope)

    def test_every_failure_exit_after_the_claim_leaves_the_witness(self):
        self.assertEqual(self.fetch.count("_tokenLanes.noteFetchFailed(lane);"), 3,
                         "request does not fit, client init failed, and the end of a fetch that did not succeed")
        end = self.fetch.rindex("return success;")
        self.assertIn("if (!success)", self.fetch[end - 120:end])

    def test_the_cached_token_is_reserved_once_at_init_so_the_install_never_allocates(self):
        self.assertIn("_bearerHeader.reserve();", self.init)
        self.assertIn("_bearerHeader.set(tokenStr);", self.fetch)
        hpp = read("TelephonyAnchorClient.hpp")
        self.assertIn("telephony::BearerHeader _bearerHeader;", hpp, "the cached bearer is the PSRAM-backed class")
        self.assertNotIn("_accessToken", hpp, "the second copy of the token is gone")
        self.assertNotIn("_accessToken", self.cpp)


if __name__ == "__main__":
    unittest.main()
