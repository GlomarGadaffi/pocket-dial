"""#986 slice 4: pin, at the source level, that no web-side hash runs under AdminAuth's mutex.

AdminLoginUnlocked_test.cpp proves the behaviour with a hash parked by a host-only hook:
the DTMF begin/finish return while a login is mid-hash, hashes run one at a time, and a
credential or lockout that changes meanwhile ends the login as a refusal that counts
nothing. What a host test cannot see is the shape of the source: that every call to the
hash in AdminAuth.cpp sits where state().mutex is not held, that the one-at-a-time mutex
is taken by hashers only and never by the SIP, tick or DTMF-worker path, and that the
refusals come before any accounting. These pins fail if a later edit puts a hash back
under the lock even when a test seam hides it.
"""
import os
import re
import unittest

REPO = os.path.join(os.path.dirname(__file__), "..", "..")
SRC = os.path.join(REPO, "src")


def code(path):
    """Source with // and /* */ comments removed, so a comment can't satisfy a pin."""
    with open(os.path.join(SRC, path), encoding="utf-8") as f:
        text = f.read()
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def func_body(text, signature):
    """Body of the function whose header matches `signature` (a regex ending before the '{'),
    found by matching braces, so it works for a method at any indentation."""
    m = re.search(signature + r"[^{;]*\{", text, re.S)
    assert m, signature + " not found"
    depth, i = 1, m.end()
    while depth:
        c = text[i]
        depth += (c == "{") - (c == "}")
        i += 1
    return text[m.end():i - 1]


HASH = "hashSecretOneAtATime("

LOGINS = (
    ("verifyCredential", r"bool verifyCredential\(", "recordAttemptLocked(", "return false;"),
    ("authenticate", r"Role authenticate\(", "recordBucketAttemptLocked(", "return Role::None;"),
)
SETTERS = (
    ("setLoginCredential", r"bool setLoginCredential\("),
    ("setOwnerCredential", r"bool setOwnerCredential\("),
    ("setDtmfPin", r"bool setDtmfPin\("),
)


class TheLoginHashesWithTheMutexReleased(unittest.TestCase):
    def setUp(self):
        self.auth = code("Helpers/AdminAuth.cpp")

    def test_the_hash_sits_between_an_unlock_and_a_lock(self):
        for name, sig, record, _ in LOGINS:
            b = func_body(self.auth, sig)
            self.assertEqual(b.count(HASH), 1, name + ": one hash")
            self.assertNotIn("hashSecret(", b, name + ": only through the one-at-a-time wrapper")
            self.assertEqual(b.count("lock.unlock();"), 1, name)
            self.assertEqual(b.count("lock.lock();"), 1, name)
            self.assertIn("std::unique_lock<std::mutex> lock(s.mutex);", b, name)
            self.assertNotIn("lock_guard", b, name + ": a guard cannot be released for the hash")
            snap = b.index("snapshotLoginLocked(")
            self.assertLess(b.index("loadCredentialLocked(s);"), snap, name + ": snapshot under the lock")
            self.assertLess(snap, b.index("lock.unlock();"), name + ": copy first, then release")
            self.assertLess(b.index("lock.unlock();"), b.index(HASH), name + ": hash with the mutex released")
            self.assertLess(b.index(HASH), b.index("lock.lock();"), name + ": relock only after the hash")
            self.assertLess(b.index("lock.lock();"), b.index(record), name + ": account after relocking")

    def test_the_hash_does_not_depend_on_the_username(self):
        # A wrong username must cost the same wall-clock as a wrong password (the comment above
        # verifyCredential): nothing between the snapshot and the hash may look at the username.
        for name, sig, _, _ in LOGINS:
            b = func_body(self.auth, sig)
            snap = b.index("snapshotLoginLocked(")
            between = b[b.index(";", snap):b.index(HASH)]
            self.assertNotIn("username", between, name)
            self.assertNotIn("userOk", between, name)
            self.assertIn("ok = snap.userOk && passOk;", b, name)
            self.assertLess(b.index("bool passOk"), b.index("ok = snap.userOk && passOk;"),
                            name + ": both compares are made before they are combined")

    def test_a_changed_credential_or_a_new_lockout_refuses_before_any_accounting(self):
        for name, sig, record, refusal in LOGINS:
            b = func_body(self.auth, sig)
            after = b[b.index("lock.lock();"):b.index(record)]
            # exactly two ways out between the relock and the accounting: stale, and locked out.
            # Misses leave that way too: a miss recorded under an engaged lockout would escalate
            # the next cooldown, which the serial code never did (it refused at the pre-check).
            self.assertEqual(after.count("return"), 2, name)
            self.assertEqual(after.count(refusal), 2, name)
            stale = after.index("loginSnapshotCurrentLocked(")
            bucket = after.index("acquireBucketLocked(")
            locked = after.index("LockedOutLocked(")
            self.assertLess(stale, bucket, name + ": stale check first")
            self.assertLess(bucket, locked, name + ": the bucket we held may have been recycled while unlocked")
            self.assertLess(locked, after.index("constantTimeEquals(candidate"), name)
            self.assertLess(after.index(refusal, locked), after.index("constantTimeEquals(candidate"), name)

    def test_the_default_credential_still_hashes_nothing(self):
        for name, sig, _, _ in LOGINS:
            b = func_body(self.auth, sig)
            self.assertIn("kDefaultUsername", b, name)
            self.assertLess(b.index("kDefaultUsername"), b.index("snapshotLoginLocked("), name)

    def test_the_stale_check_compares_the_salt_and_the_hash_of_the_right_principal(self):
        b = func_body(self.auth, r"bool loginSnapshotCurrentLocked\(")
        self.assertIn("s.ownerProvisioned && s.ownerPwSalt == snap.salt && s.ownerPwHash == snap.hash", b)
        self.assertIn("s.provisioned && s.pwSalt == snap.salt && s.pwHash == snap.hash", b)


class TheSettersHashBeforeTheyLock(unittest.TestCase):
    def setUp(self):
        self.auth = code("Helpers/AdminAuth.cpp")

    def test_the_hash_comes_before_the_credential_mutex_is_taken(self):
        for name, sig in SETTERS:
            b = func_body(self.auth, sig)
            self.assertEqual(b.count(HASH), 1, name)
            self.assertNotIn("hashSecret(", b, name)
            self.assertLess(b.index("randomHex(32)"), b.index(HASH), name)
            self.assertLess(b.index(HASH), b.index("std::lock_guard<std::mutex> lock(s.mutex);"), name)
            self.assertLess(b.index("std::lock_guard<std::mutex> lock(s.mutex);"), b.index("persist"), name)

    def test_the_rng_is_guarded_now_that_the_salt_is_drawn_outside_the_mutex(self):
        b = func_body(self.auth, r"void fillRandom\(")
        host = b[b.index("#else"):]
        self.assertIn("std::lock_guard<std::mutex>", host)
        self.assertLess(host.index("std::lock_guard<std::mutex>"), host.index("rng()"))


class TheHashMutexIsTakenByHashersOnly(unittest.TestCase):
    def setUp(self):
        self.auth = code("Helpers/AdminAuth.cpp")
        with open(os.path.join(SRC, "Helpers", "AdminAuth.cpp"), encoding="utf-8") as f:
            self.raw = f.read()

    def test_the_wrapper_takes_it_and_it_is_the_only_place_that_does(self):
        w = func_body(self.auth, r"std::string hashSecretOneAtATime\(")
        self.assertIn("std::lock_guard<std::mutex> oneAtATime(state().hashMutex);", w)
        self.assertLess(w.index("hashMutex"), w.index("return hashSecret(salt, secret);"))
        self.assertEqual(self.auth.count("hashMutex"), 2, "the member and the wrapper")
        self.assertEqual(len(re.findall(r"\bhashSecret\(", self.auth)), 2, "its definition and the wrapper's call")
        # every call site, by function: six callers, one hash each
        self.assertEqual(self.auth.count(HASH), 7, "the wrapper's definition and six calls")
        self.assertEqual(func_body(self.auth, r"std::string loginHashForTest\(").count(HASH), 1)

    def test_the_lock_order_is_written_down_where_the_mutex_is_taken(self):
        before = self.raw[:self.raw.index("std::string hashSecretOneAtATime(")]
        comment = before[before.rindex("// Every web-side hash"):]
        self.assertIn("LOCK ORDER", comment)
        self.assertIn("state().mutex", comment)
        self.assertIn("clearCredential()", comment)

    def test_no_other_file_reaches_the_wrapper_or_the_mutex(self):
        for root in ("src", "main"):
            for d, _, files in os.walk(os.path.join(REPO, root)):
                for name in files:
                    if not name.endswith((".cpp", ".hpp", ".h", ".c")) or name == "AdminAuth.cpp":
                        continue
                    with open(os.path.join(d, name), encoding="utf-8", errors="replace") as f:
                        text = re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", "", f.read(), flags=re.S))
                    for bad in ("hashMutex", "hashSecretOneAtATime"):
                        self.assertNotIn(bad, text, os.path.join(d, name))

    def test_the_sip_tick_and_dtmf_paths_never_take_it(self):
        for sig in (r"bool beginDtmfPinVerify\(", r"bool matchesDtmfPin\(", r"bool finishDtmfPinVerify\(",
                    r"bool verifyDtmfPin\(", r"bool clearCredential\(", r"bool isLockedOut\(",
                    r"void hashSecretDigest\("):
            b = func_body(self.auth, sig)
            for bad in ("hashMutex", HASH, "hashSecret("):
                self.assertNotIn(bad, b, sig)


if __name__ == "__main__":
    unittest.main()
