from __future__ import annotations

import unittest

import httpx

from backend.app.ai.client import _format_response_error


class AIClientErrorTest(unittest.TestCase):
    def test_format_response_error_keeps_provider_code_and_message(self) -> None:
        response = httpx.Response(
            400,
            json={
                "error": {
                    "message": "The free tier of the model has been exhausted.",
                    "code": "AllocationQuota.FreeTierOnly",
                }
            },
        )

        self.assertEqual(
            _format_response_error(response),
            "400 AllocationQuota.FreeTierOnly: The free tier of the model has been exhausted.",
        )


if __name__ == "__main__":
    unittest.main()
