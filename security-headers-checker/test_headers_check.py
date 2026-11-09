import unittest
from pathlib import Path

import headers_check as hc

SAMPLES = Path(__file__).parent / "samples"


def by_header(findings):
    return {f.header: f for f in findings}


class TestHeaders(unittest.TestCase):
    def test_parse_ignores_status_line_and_is_case_insensitive(self):
        h = hc.parse_headers("HTTP/2 200\nContent-Type: text/html\nSET-COOKIE: a=1\nset-cookie: b=2")
        self.assertEqual(h["content-type"], ["text/html"])
        self.assertEqual(h["set-cookie"], ["a=1", "b=2"])
        self.assertNotIn("http/2 200", h)

    def test_bad_sample(self):
        f = by_header(hc.audit((SAMPLES / "mauvais_exemple.txt").read_text()))
        self.assertEqual(f["Strict-Transport-Security"].status, hc.FAIL)
        self.assertEqual(f["Content-Security-Policy"].status, hc.WARN)
        self.assertIn("unsafe-inline", f["Content-Security-Policy"].message)
        self.assertEqual(f["X-Content-Type-Options"].status, hc.FAIL)
        self.assertEqual(f["Fuite d'informations"].status, hc.WARN)
        self.assertEqual(f["Cookies"].status, hc.WARN)
        self.assertIn("PHPSESSID", f["Cookies"].message)

    def test_good_sample_is_perfect(self):
        findings = hc.audit((SAMPLES / "bon_exemple.txt").read_text())
        self.assertTrue(all(x.status == hc.OK for x in findings), [x for x in findings if x.status != hc.OK])
        self.assertEqual(hc.score(findings), 100)

    def test_short_hsts_is_a_warning(self):
        f = hc.check_hsts(hc.parse_headers("Strict-Transport-Security: max-age=300"))
        self.assertEqual(f.status, hc.WARN)

    def test_frame_ancestors_counts_as_clickjacking_protection(self):
        h = hc.parse_headers("Content-Security-Policy: default-src 'self'; frame-ancestors 'self'")
        self.assertEqual(hc.check_framing(h).status, hc.OK)

    def test_bad_score_is_low(self):
        self.assertLess(hc.score(hc.audit((SAMPLES / "mauvais_exemple.txt").read_text())), 30)


if __name__ == "__main__":
    unittest.main()
