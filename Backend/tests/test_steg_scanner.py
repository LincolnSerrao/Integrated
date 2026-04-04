import tempfile
import unittest
from pathlib import Path

from app.steg_scanner import scan_image


PNG_BASE = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR"
    b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"
    b"\x90wS\xde"
    b"\x00\x00\x00\x00IEND\xaeB`\x82"
)

JPEG_BASE = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x02\x00\x00\x01\x00\x01\x00\x00\xff\xd9"


class StegScannerTests(unittest.TestCase):
    def _scan_bytes(self, suffix: str, payload: bytes):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / f"sample{suffix}"
            path.write_bytes(payload)
            return scan_image(path)

    def test_png_without_appended_data_is_allowed(self):
        result = self._scan_bytes('.png', PNG_BASE)
        self.assertEqual(result['decision'], 'ALLOWED')
        self.assertEqual(result['engine'], 'steg')

    def test_png_with_appended_data_is_blocked(self):
        result = self._scan_bytes('.png', PNG_BASE + b'hidden')
        self.assertEqual(result['decision'], 'BLOCKED')
        self.assertIn('Appended data detected', result['reasons'][0])

    def test_jpeg_with_appended_data_is_blocked(self):
        result = self._scan_bytes('.jpg', JPEG_BASE + b'payload')
        self.assertEqual(result['decision'], 'BLOCKED')
        self.assertIn('Appended data detected', result['reasons'][0])

    def test_unknown_format_is_uncertain(self):
        result = self._scan_bytes('.bin', b'not-an-image')
        self.assertEqual(result['decision'], 'UNCERTAIN')
        self.assertIn('Not a recognized', result['reasons'][0])


if __name__ == '__main__':
    unittest.main()
