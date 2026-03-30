from __future__ import annotations

import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from sse_user_counter.cli import build_config, prompt_if_missing


class CliTests(unittest.TestCase):
    def test_prompt_if_missing_asks_for_swg_correlation_choice(self) -> None:
        args = Namespace(
            product="umbrella",
            api_key="key",
            api_secret="secret",
            org_id="",
            swg_correlate_identities=None,
            reporting_region="auto",
            swg_correlation_days=30,
            vpn_days=60,
            output_root=Path("output"),
        )

        with patch("builtins.input", side_effect=["", "yes"]):
            completed = prompt_if_missing(args)

        self.assertEqual(completed.org_id, "")
        self.assertEqual(completed.swg_correlate_identities, "yes")

    def test_build_config_maps_yes_no_swg_correlation_flag(self) -> None:
        yes_args = Namespace(
            product="secure-access",
            api_key="key",
            api_secret="secret",
            org_id="",
            swg_correlate_identities="yes",
            reporting_region="auto",
            swg_correlation_days=30,
            vpn_days=60,
            output_root=Path("output"),
        )
        no_args = Namespace(
            product="secure-access",
            api_key="key",
            api_secret="secret",
            org_id="",
            swg_correlate_identities="no",
            reporting_region="auto",
            swg_correlation_days=30,
            vpn_days=60,
            output_root=Path("output"),
        )

        _, yes_config = build_config(yes_args)
        _, no_config = build_config(no_args)

        self.assertTrue(yes_config.swg_correlate_identities)
        self.assertFalse(no_config.swg_correlate_identities)


if __name__ == "__main__":
    unittest.main()
