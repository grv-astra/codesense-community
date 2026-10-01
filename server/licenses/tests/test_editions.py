from django.test import SimpleTestCase

from licenses.editions import EDITIONS, DEFAULT_EDITION, FEATURE_KEYS, LIMIT_KEYS


class EditionsCatalogTests(SimpleTestCase):
    def test_default_edition_is_community(self):
        self.assertEqual(DEFAULT_EDITION, "community")
        self.assertIn(DEFAULT_EDITION, EDITIONS)

    def test_three_editions_present(self):
        self.assertEqual(set(EDITIONS), {"community", "pro", "enterprise"})

    def test_every_edition_defines_every_feature_and_limit(self):
        for name, spec in EDITIONS.items():
            self.assertEqual(set(spec["features"]), set(FEATURE_KEYS), name)
            self.assertEqual(set(spec["limits"]), set(LIMIT_KEYS), name)
            self.assertIn(spec["model_tier"], {"low", "mid", "high"}, name)
            self.assertTrue(spec["label"], name)

    def test_community_is_deterministic_only(self):
        f = EDITIONS["community"]["features"]
        self.assertFalse(f["llm_analysis"])
        self.assertFalse(f["sbom_signing"])
        self.assertFalse(f["api_access"])
        self.assertFalse(f["incremental_scan"])
        self.assertTrue(f["github_scan"])

    def test_enterprise_is_unlimited(self):
        for k, v in EDITIONS["enterprise"]["limits"].items():
            if k == "window_days":
                self.assertEqual(v, 30)
            else:
                self.assertIsNone(v)

    def test_monotonic_limits_community_le_pro_le_enterprise(self):
        def val(ed, key):
            v = EDITIONS[ed]["limits"][key]
            return float("inf") if v is None else v
        for key in ("projects", "code_scans_per_window", "sbom_scans_per_window", "seats", "max_codebase_mb"):
            self.assertLessEqual(val("community", key), val("pro", key), key)
            self.assertLessEqual(val("pro", key), val("enterprise", key), key)

    def test_edition_spec_returns_entry_and_falls_back(self):
        from licenses.editions import edition_spec
        self.assertIs(edition_spec("pro"), EDITIONS["pro"])
        self.assertIs(edition_spec("nonsense"), EDITIONS["community"])

    def test_public_catalog_is_ordered_and_complete_and_copied(self):
        from licenses.editions import public_catalog
        cat = public_catalog()
        self.assertEqual([e["edition"] for e in cat], ["community", "pro", "enterprise"])
        for entry in cat:
            self.assertEqual(set(entry["features"]), set(FEATURE_KEYS), entry["edition"])
            self.assertEqual(set(entry["limits"]), set(LIMIT_KEYS), entry["edition"])
            self.assertTrue(entry["label"])
            self.assertIn(entry["model_tier"], {"low", "mid", "high"})
        # copies, not the live dict -- mutating a result must not affect EDITIONS
        cat[0]["features"]["llm_analysis"] = True
        self.assertFalse(EDITIONS["community"]["features"]["llm_analysis"])
