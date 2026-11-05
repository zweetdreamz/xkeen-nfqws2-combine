"""Unit tests of kdn.common.errors: the typed errors of the panel and the HTTP status each one carries."""

from __future__ import annotations

import unittest

from kdn.common import errors


class ErrorsTests(unittest.TestCase):
    def test_statuses(self):
        self.assertEqual(
            {
                "PanelError": errors.PanelError.status,
                "BadRequest": errors.BadRequest.status,
                "NotFound": errors.NotFound.status,
                "Busy": errors.Busy.status,
                "Upstream": errors.Upstream.status,
            },
            {"PanelError": 500, "BadRequest": 400, "NotFound": 404, "Busy": 409, "Upstream": 502},
        )
        # The status is a property of the class; an instance reports the same one.
        self.assertEqual(errors.Busy("занято").status, 409)

    def test_base_classes(self):
        for cls in (errors.BadRequest, errors.NotFound, errors.Busy, errors.Upstream):
            with self.subTest(error=cls.__name__):
                self.assertTrue(issubclass(cls, errors.PanelError))
        self.assertTrue(issubclass(errors.Busy, RuntimeError))
        self.assertTrue(issubclass(errors.BadRequest, ValueError))
        self.assertTrue(issubclass(errors.NotFound, LookupError))
        self.assertFalse(issubclass(errors.Upstream, (RuntimeError, ValueError, LookupError)))
        self.assertFalse(issubclass(errors.Busy, (ValueError, LookupError)))
        self.assertFalse(issubclass(errors.BadRequest, (RuntimeError, LookupError)))
        self.assertFalse(issubclass(errors.NotFound, (RuntimeError, ValueError)))
        self.assertTrue(issubclass(errors.PanelError, Exception))

    def test_str_is_the_message(self):
        for cls in (errors.PanelError, errors.BadRequest, errors.NotFound, errors.Busy, errors.Upstream):
            with self.subTest(error=cls.__name__):
                self.assertEqual(str(cls("текст отказа: 42")), "текст отказа: 42")
                self.assertEqual(cls("текст").args, ("текст",))

    def test_old_handlers_still_catch_the_new_errors(self):
        # The old code maps RuntimeError to 409 and ValueError to 400: a typed error keeps working there.
        with self.assertRaises(RuntimeError):
            raise errors.Busy("занято")
        with self.assertRaises(ValueError):
            raise errors.BadRequest("неверно")
        with self.assertRaises(LookupError):
            raise errors.NotFound("нет")


if __name__ == "__main__":
    unittest.main()
