import io
import unittest
from unittest.mock import patch

from PIL import Image

from app.services.image_ocr import MAX_IMAGE_PIXELS, OCR_TIMEOUT_SECONDS, extract_text_from_image


class ImageOCRTests(unittest.TestCase):
    def _png(self) -> bytes:
        image = Image.new("RGB", (16, 16), "white")
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return buffer.getvalue()

    def test_ocr_has_a_timeout_and_normalizes_extracted_text(self) -> None:
        with patch("pytesseract.image_to_string", return_value="  Visit   https://example.org/login \n") as ocr:
            result = extract_text_from_image(self._png())

        self.assertEqual(result, "Visit https://example.org/login")
        self.assertEqual(ocr.call_args.kwargs["timeout"], OCR_TIMEOUT_SECONDS)

    def test_oversized_image_dimensions_are_rejected_before_ocr(self) -> None:
        oversized_image = type(
            "ImageDimensions",
            (),
            {"format": "PNG", "width": MAX_IMAGE_PIXELS + 1, "height": 1},
        )()
        with patch("PIL.Image.open", return_value=oversized_image), patch(
            "pytesseract.image_to_string"
        ) as ocr:
            with self.assertRaisesRegex(ValueError, "dimensions exceed"):
                extract_text_from_image(b"image bytes")

        ocr.assert_not_called()


if __name__ == "__main__":
    unittest.main()
