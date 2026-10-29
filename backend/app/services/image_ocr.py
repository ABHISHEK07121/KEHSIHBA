import io
import os

MAX_IMAGE_PIXELS = 20_000_000
OCR_TIMEOUT_SECONDS = 8
SUPPORTED_IMAGE_FORMATS = {"PNG", "JPEG", "WEBP"}

def extract_text_from_image(content: bytes) -> str:
    import pytesseract
    from PIL import Image, ImageOps

    if os.getenv("TESSERACT_CMD"):
        pytesseract.pytesseract.tesseract_cmd = os.environ["TESSERACT_CMD"]
    image = Image.open(io.BytesIO(content))
    if image.format not in SUPPORTED_IMAGE_FORMATS:
        raise ValueError("Unsupported image format.")
    if image.width * image.height > MAX_IMAGE_PIXELS:
        raise ValueError("Image dimensions exceed the OCR limit.")
    image = ImageOps.grayscale(image)
    text = pytesseract.image_to_string(image, timeout=OCR_TIMEOUT_SECONDS)
    return " ".join(text.split())
