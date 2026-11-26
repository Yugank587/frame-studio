import io
import json
import hashlib
import hmac
import math
import mimetypes
import os
import secrets
import shutil
import smtplib
import ssl
import tempfile
import threading
import zipfile
from email.message import EmailMessage
from email import policy
from email.parser import BytesParser
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from time import time, time_ns
from urllib.parse import parse_qs, unquote, urlparse

from PIL import Image, ImageEnhance, ImageFilter, ImageOps

try:
    import win32crypt
except ImportError:
    win32crypt = None


HOST = "127.0.0.1"
PORT = 8000
STATIC_DIR = Path(__file__).resolve().parent / "Static"
UPLOAD_DIR = Path(__file__).resolve().parent / "Uploads"
MODEL_DIR = Path(__file__).resolve().parent / "Models"
AUTH_BASE_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
AUTH_FILE = AUTH_BASE_DIR / "FrameStudio" / "auth.json"
MAX_UPLOAD_SIZE = 512 * 1024 * 1024
MAX_DOCUMENT_SIZE = 128 * 1024 * 1024
SESSION_TTL_SECONDS = 12 * 60 * 60
PHASH_DISTANCE_THRESHOLD = 10
IMAGE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".heic"
}
DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx"}
DCT_COSINES = tuple(
    tuple(math.cos((2 * position + 1) * frequency * math.pi / 64) for position in range(32))
    for frequency in range(8)
)
_rembg_session = None
_rembg_lock = threading.Lock()
_auth_lock = threading.Lock()
_sessions_lock = threading.Lock()
_sessions = {}
_recovery_lock = threading.Lock()
_pending_email_verifications = {}
_pending_password_resets = {}
_last_recovery_request = {}
_last_verification_request = {}
SESSION_COOKIE_NAME = "frame_studio_session"
RECOVERY_CODE_TTL_SECONDS = 10 * 60
PASSWORD_RESET_TTL_SECONDS = 30 * 60
RECOVERY_REQUEST_COOLDOWN_SECONDS = 60


class BackgroundRemovalError(Exception):
    pass


class DocumentConversionError(Exception):
    pass


def load_credentials():
    try:
        credentials = json.loads(AUTH_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Saved login settings could not be read.") from exc

    if (
        not isinstance(credentials, dict)
        or not isinstance(credentials.get("username"), str)
        or not isinstance(credentials.get("salt"), str)
        or not isinstance(credentials.get("password_hash"), str)
    ):
        raise RuntimeError("Saved login settings are invalid.")
    return credentials


def write_credentials(credentials):
    AUTH_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = AUTH_FILE.with_name("auth-%s.tmp" % secrets.token_hex(8))
    try:
        temporary_path.write_text(json.dumps(credentials), encoding="utf-8")
        os.replace(temporary_path, AUTH_FILE)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def password_hash(password, salt):
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    ).hex()


def save_credentials(username, password):
    salt = secrets.token_bytes(16)
    write_credentials({
        "username": username,
        "salt": salt.hex(),
        "password_hash": password_hash(password, salt),
    })


def update_password(credentials, password):
    salt = secrets.token_bytes(16)
    credentials["salt"] = salt.hex()
    credentials["password_hash"] = password_hash(password, salt)


def protect_smtp_password(password):
    if win32crypt is None:
        raise RuntimeError("Secure email storage is unavailable. Install the Windows dependencies and restart Frame Studio.")
    return win32crypt.CryptProtectData(
        password.encode("utf-8"),
        "Frame Studio SMTP password",
        None,
        None,
        None,
        0,
    ).hex()


def unprotect_smtp_password(encrypted_password):
    if win32crypt is None:
        raise RuntimeError("Secure email storage is unavailable. Install the Windows dependencies and restart Frame Studio.")
    return win32crypt.CryptUnprotectData(
        bytes.fromhex(encrypted_password),
        None,
        None,
        None,
        0,
    )[1].decode("utf-8")


def valid_email_address(value):
    if not isinstance(value, str):
        return False
    address = value.strip()
    return (
        len(address) <= 254
        and "\r" not in address
        and "\n" not in address
        and address.count("@") == 1
        and all(not character.isspace() for character in address)
        and "." in address.rsplit("@", 1)[1]
    )


def make_smtp_settings(body, credentials):
    host = body.get("smtpHost")
    username = body.get("smtpUsername")
    sender = body.get("smtpSender")
    password = body.get("smtpPassword")
    try:
        port = int(body.get("smtpPort"))
    except (TypeError, ValueError) as exc:
        raise ValueError("Enter a valid SMTP port.") from exc

    if (
        not isinstance(host, str) or not host.strip()
        or len(host.strip()) > 253 or any(character.isspace() for character in host.strip())
    ):
        raise ValueError("Enter a valid SMTP server host.")
    if not 1 <= port <= 65535:
        raise ValueError("SMTP port must be between 1 and 65535.")
    if not isinstance(username, str) or not username.strip() or len(username) > 254:
        raise ValueError("Enter the SMTP account username.")
    if not valid_email_address(sender):
        raise ValueError("Enter a valid sender email address.")
    if not isinstance(password, str):
        raise ValueError("Enter the SMTP app password.")

    encrypted_password = password.strip()
    if encrypted_password:
        encrypted_password = protect_smtp_password(encrypted_password)
    else:
        encrypted_password = credentials.get("smtp_password_encrypted", "")
        if not encrypted_password:
            raise ValueError("Enter the SMTP app password.")

    return {
        "smtp_host": host.strip(),
        "smtp_port": port,
        "smtp_username": username.strip(),
        "smtp_sender": sender.strip(),
        "smtp_password_encrypted": encrypted_password,
    }


def send_account_email(credentials, recipient, subject, body):
    encrypted_password = credentials.get("smtp_password_encrypted")
    if not encrypted_password:
        raise RuntimeError("Email recovery has not been configured.")
    password = unprotect_smtp_password(encrypted_password)
    host = credentials.get("smtp_host", "")
    port = int(credentials.get("smtp_port", 0))
    username = credentials.get("smtp_username", "")
    sender = credentials.get("smtp_sender", "")
    if not host or not port or not username or not sender:
        raise RuntimeError("Email recovery settings are incomplete.")

    message = EmailMessage()
    message["From"] = sender
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)

    if port == 465:
        with smtplib.SMTP_SSL(host, port, timeout=15, context=ssl.create_default_context()) as server:
            server.login(username, password)
            server.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=15) as server:
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
            server.login(username, password)
            server.send_message(message)


def perceptual_hash(path):
    with Image.open(path) as source:
        image = ImageOps.exif_transpose(source).convert("L").resize(
            (32, 32), Image.Resampling.LANCZOS
        )

    pixels = list(image.get_flattened_data())
    coefficients = []
    for vertical in range(8):
        for horizontal in range(8):
            coefficient = 0.0
            for y in range(32):
                for x in range(32):
                    coefficient += (
                        pixels[y * 32 + x]
                        * DCT_COSINES[horizontal][x]
                        * DCT_COSINES[vertical][y]
                    )
            if horizontal or vertical:
                coefficients.append(coefficient)

    median = sorted(coefficients)[len(coefficients) // 2]
    return sum(
        1 << index
        for index, coefficient in enumerate(coefficients)
        if coefficient > median
    )


def group_images(paths):
    images = []
    hashes = []
    for path in paths:
        stat = path.stat()
        images.append({
            "name": path.name,
            "path": str(path),
            "size": stat.st_size,
            "modified": stat.st_mtime,
        })
        try:
            hashes.append(perceptual_hash(path))
        except (OSError, ValueError, Image.DecompressionBombError):
            hashes.append(None)

    parents = list(range(len(images)))

    def find(index):
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    for left in range(len(images)):
        if hashes[left] is None:
            continue
        for right in range(left + 1, len(images)):
            if hashes[right] is not None and (
                hashes[left] ^ hashes[right]
            ).bit_count() <= PHASH_DISTANCE_THRESHOLD:
                left_root = find(left)
                right_root = find(right)
                if left_root != right_root:
                    parents[right_root] = left_root

    grouped = {}
    for index, image in enumerate(images):
        grouped.setdefault(find(index), []).append(image)

    return [
        {"id": group_index, "similar": len(group) > 1, "images": group}
        for group_index, group in enumerate(grouped.values(), start=1)
    ]


def uploaded_image(filename):
    if not isinstance(filename, str) or not filename or "/" in filename or "\\" in filename:
        raise ValueError("Invalid image name.")
    path = (UPLOAD_DIR / filename).resolve(strict=True)
    if path.parent != UPLOAD_DIR.resolve() or not path.is_file():
        raise ValueError("Image not found.")
    if path.suffix.lower() not in IMAGE_EXTENSIONS:
        raise ValueError("Unsupported image format.")
    return path


def remove_image_background(image):
    global _rembg_session
    try:
        os.environ.setdefault("U2NET_HOME", str(MODEL_DIR))
        from rembg import new_session, remove
    except ImportError as exc:
        raise BackgroundRemovalError(
            "Background removal needs the app's Python 3.13 environment and dependencies."
        ) from exc

    try:
        with _rembg_lock:
            if _rembg_session is None:
                _rembg_session = new_session("u2net")
            result = remove(image, session=_rembg_session)
    except Exception as exc:
        raise BackgroundRemovalError("Local AI background removal failed: %s" % exc) from exc

    if not isinstance(result, Image.Image):
        raise BackgroundRemovalError("The background-removal model returned an invalid image.")
    return result


def edit_adjustment_value(body, name, default, minimum, maximum):
    value = body.get(name, default)
    if (
        isinstance(value, bool) or not isinstance(value, (int, float))
        or not minimum <= value <= maximum
    ):
        raise ValueError("%s must be between %s and %s." % (name.capitalize(), minimum, maximum))
    return float(value)


def apply_image_adjustments(image, body):
    brightness = edit_adjustment_value(body, "brightness", 100, 0, 200)
    contrast = edit_adjustment_value(body, "contrast", 100, 0, 200)
    saturation = edit_adjustment_value(body, "saturation", 100, 0, 200)
    warmth = edit_adjustment_value(body, "warmth", 0, -100, 100)
    sharpness = edit_adjustment_value(body, "sharpness", 100, 0, 200)
    blur = edit_adjustment_value(body, "blur", 0, 0, 20)
    preset = body.get("filterPreset", "none")
    if not isinstance(preset, str) or preset not in {
        "none", "warm", "cool", "vivid", "vintage", "mono", "sepia", "soft"
    }:
        raise ValueError("Choose a supported filter preset.")

    presets = {
        "none": (1.0, 1.0, 1.0, 0, 0),
        "warm": (1.02, 1.0, 1.08, 24, 0),
        "cool": (1.0, 1.02, 0.96, -24, 0),
        "vivid": (1.02, 1.12, 1.3, 0, 0),
        "vintage": (1.04, 0.9, 0.76, 18, 0.2),
        "mono": (1.0, 1.0, 1.0, 0, 0),
        "sepia": (1.0, 1.0, 1.0, 0, 0),
        "soft": (1.03, 0.94, 0.9, 0, 0.6),
    }
    preset_brightness, preset_contrast, preset_saturation, preset_warmth, preset_blur = presets[preset]
    alpha = image.getchannel("A") if "A" in image.getbands() else None
    image = image.convert("RGB")
    image = ImageEnhance.Brightness(image).enhance(brightness / 100 * preset_brightness)
    image = ImageEnhance.Contrast(image).enhance(contrast / 100 * preset_contrast)
    image = ImageEnhance.Color(image).enhance(saturation / 100 * preset_saturation)

    warmth += preset_warmth
    if warmth:
        shift = warmth * 0.35
        red, green, blue = image.split()
        red = red.point(lambda value: max(0, min(255, round(value + shift))))
        blue = blue.point(lambda value: max(0, min(255, round(value - shift))))
        image = Image.merge("RGB", (red, green, blue))

    if preset == "mono":
        image = ImageOps.grayscale(image).convert("RGB")
    elif preset == "sepia":
        image = ImageOps.colorize(ImageOps.grayscale(image), "#3c2b21", "#f1dfbd")

    image = ImageEnhance.Sharpness(image).enhance(sharpness / 100)
    blur += preset_blur
    if blur:
        image = image.filter(ImageFilter.GaussianBlur(radius=blur))
    if alpha is not None:
        image.putalpha(alpha)
    return image


def edited_image(body):
    path = uploaded_image(body.get("filename"))
    with Image.open(path) as source:
        image = ImageOps.exif_transpose(source)
        image.load()
        image = image.convert("RGBA" if "A" in image.getbands() else "RGB")

    if body.get("removeBackground"):
        image = remove_image_background(image)

    crop = body.get("crop")
    if crop is not None:
        if not isinstance(crop, dict):
            raise ValueError("Invalid crop area.")
        values = [crop.get(key) for key in ("x", "y", "width", "height")]
        if any(not isinstance(value, int) or isinstance(value, bool) for value in values):
            raise ValueError("Crop coordinates must be whole numbers.")
        x, y, width, height = values
        if x < 0 or y < 0 or width <= 0 or height <= 0:
            raise ValueError("Crop area must be a positive rectangle.")
        if x + width > image.width or y + height > image.height:
            raise ValueError("Crop area is outside the image.")
        image = image.crop((x, y, x + width, y + height))

    size = body.get("size")
    if size is not None:
        if not isinstance(size, dict):
            raise ValueError("Invalid output size.")
        width, height = size.get("width"), size.get("height")
        if (
            not isinstance(width, int) or isinstance(width, bool)
            or not isinstance(height, int) or isinstance(height, bool)
            or width < 1 or height < 1 or width > 24000 or height > 24000
            or width * height > 100_000_000
        ):
            raise ValueError("Output dimensions are invalid or too large.")
        image = image.resize((width, height), Image.Resampling.LANCZOS)

    output_format = body.get("format", "png")
    if output_format not in {"png", "jpeg", "webp", "bmp", "tiff", "pdf"}:
        raise ValueError("Unsupported output format.")
    if body.get("removeBackground") and output_format in {"jpeg", "bmp", "pdf"}:
        raise ValueError("Choose PNG, WebP, or TIFF to keep the transparent background.")

    quality = body.get("quality", 95)
    if not isinstance(quality, int) or isinstance(quality, bool) or not 1 <= quality <= 100:
        raise ValueError("Quality must be between 1 and 100.")

    image = apply_image_adjustments(image, body)
    output = io.BytesIO()
    if output_format == "pdf":
        if image.mode == "RGBA":
            background = Image.new("RGB", image.size, "white")
            background.paste(image, mask=image.getchannel("A"))
            image = background
        elif image.mode != "RGB":
            image = image.convert("RGB")
        image.save(output, format="PDF", resolution=300, quality=100, subsampling=0)
        extension = ".pdf"
        content_type = "application/pdf"
    else:
        save_options = {}
        if output_format in {"jpeg", "bmp"} and image.mode not in {"RGB", "L"}:
            if output_format == "jpeg" and image.mode == "RGBA":
                background = Image.new("RGB", image.size, "white")
                background.paste(image, mask=image.getchannel("A"))
                image = background
            else:
                image = image.convert("RGB")
        if output_format in {"jpeg", "webp"}:
            save_options["quality"] = quality
        if output_format == "png":
            save_options["optimize"] = True
        image.save(output, format=output_format.upper(), **save_options)
        extension = ".jpg" if output_format == "jpeg" else "." + output_format
        content_type = mimetypes.types_map.get(extension, "application/octet-stream")

    filename = path.stem + "_edited" + extension
    return output.getvalue(), filename, content_type


def convert_document(input_path, output_path, output_format):
    extension = input_path.suffix.lower()
    if extension not in DOCUMENT_EXTENSIONS:
        raise ValueError("Choose a PDF, DOC, or DOCX file.")
    if output_format not in {"pdf", "docx"}:
        raise ValueError("Choose PDF or DOCX as the output format.")
    if extension == ".pdf" and output_format != "docx":
        raise ValueError("PDF files can be converted to editable DOCX documents.")
    if extension in {".doc", ".docx"} and output_format == extension.lstrip("."):
        raise ValueError("Choose a different output format from the input file.")

    if extension == ".pdf":
        try:
            from pdf2docx import Converter
        except ImportError as exc:
            raise DocumentConversionError(
                "PDF-to-Word conversion needs the app's PDF conversion dependency."
            ) from exc

        converter = None
        try:
            converter = Converter(str(input_path))
            converter.convert(str(output_path))
        except Exception as exc:
            raise DocumentConversionError(
                "Could not convert this PDF to Word: %s" % exc
            ) from exc
        finally:
            if converter is not None:
                try:
                    converter.close()
                except Exception as exc:
                    raise DocumentConversionError(
                        "Could not finish closing the PDF converter: %s" % exc
                    ) from exc
        if not output_path.is_file() or output_path.stat().st_size == 0:
            raise DocumentConversionError("PDF conversion produced an empty document.")
        return

    try:
        import pythoncom
        import win32com.client
    except ImportError as exc:
        raise DocumentConversionError(
            "Document conversion requires Microsoft Word and the app's Windows dependencies."
        ) from exc

    pythoncom.CoInitialize()
    application = None
    document = None
    conversion_error = None
    try:
        application = win32com.client.DispatchEx("Word.Application")
        application.Visible = False
        application.DisplayAlerts = 0
        application.AutomationSecurity = 3
        document = application.Documents.Open(
            str(input_path),
            ConfirmConversions=False,
            ReadOnly=True,
            AddToRecentFiles=False,
            Visible=False,
            OpenAndRepair=False,
            NoEncodingDialog=True,
        )
        document.ExportAsFixedFormat(str(output_path), 17, OpenAfterExport=False)
    except Exception as exc:
        conversion_error = exc
    finally:
        if document is not None:
            try:
                document.Close(False)
            except Exception as exc:
                if conversion_error is None:
                    conversion_error = exc
        if application is not None:
            try:
                application.Quit(False)
            except Exception as exc:
                if conversion_error is None:
                    conversion_error = exc
        try:
            pythoncom.CoUninitialize()
        except Exception as exc:
            if conversion_error is None:
                conversion_error = exc

    if conversion_error is not None:
        raise DocumentConversionError(
            "Microsoft Word could not convert this document: %s" % conversion_error
        ) from conversion_error

    if not output_path.is_file() or output_path.stat().st_size == 0:
        raise DocumentConversionError("Microsoft Word produced an empty document.")


def json_response(handler, status, payload, headers=None):
    data = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Cache-Control", "no-store")
    for name, value in (headers or {}).items():
        handler.send_header(name, value)
    handler.end_headers()
    handler.wfile.write(data)


def safe_directory(raw_path):
    if not raw_path:
        return None
    try:
        path = Path(raw_path).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        path = path.resolve()
    except (OSError, RuntimeError):
        return None
    return path if path.is_dir() else None


class ImageSorterHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print("%s - %s" % (self.address_string(), format % args))

    def session_token(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except CookieError:
            return ""
        morsel = cookie.get(SESSION_COOKIE_NAME)
        return morsel.value if morsel is not None else ""

    def is_authenticated(self):
        token = self.session_token()
        if not token:
            return False
        now = time()
        with _sessions_lock:
            expires_at = _sessions.get(token)
            if expires_at is None:
                return False
            if expires_at <= now:
                _sessions.pop(token, None)
                return False
            return True

    def create_session(self):
        token = secrets.token_urlsafe(32)
        now = time()
        with _sessions_lock:
            for existing, expires_at in list(_sessions.items()):
                if expires_at <= now:
                    _sessions.pop(existing, None)
            _sessions[token] = now + SESSION_TTL_SECONDS
        return {
            "Set-Cookie": "%s=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d"
            % (SESSION_COOKIE_NAME, token, SESSION_TTL_SECONDS)
        }

    def clear_session(self):
        token = self.session_token()
        if token:
            with _sessions_lock:
                _sessions.pop(token, None)
        return {
            "Set-Cookie": "%s=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
            % SESSION_COOKIE_NAME
        }

    def handle_auth_status(self):
        try:
            credentials = load_credentials()
        except RuntimeError as exc:
            json_response(self, 500, {"error": str(exc)})
            return
        json_response(self, 200, {
            "setupRequired": credentials is None,
            "authenticated": self.is_authenticated(),
        })

    def handle_auth_account(self):
        try:
            credentials = load_credentials()
        except RuntimeError as exc:
            json_response(self, 500, {"error": str(exc)})
            return
        if credentials is None:
            json_response(self, 409, {"error": "Create your local account first."})
            return
        json_response(self, 200, {
            "username": credentials["username"],
            "recoveryEmail": credentials.get("recovery_email", ""),
            "recoveryVerified": bool(credentials.get("recovery_verified")),
            "smtpHost": credentials.get("smtp_host", ""),
            "smtpPort": credentials.get("smtp_port", 587),
            "smtpUsername": credentials.get("smtp_username", ""),
            "smtpSender": credentials.get("smtp_sender", ""),
            "smtpConfigured": bool(credentials.get("smtp_password_encrypted")),
        })

    def handle_auth_account_update(self):
        try:
            body = self.read_json_body()
            if not isinstance(body, dict):
                raise ValueError("Invalid account update request.")
            current_password = body.get("currentPassword")
            new_username = body.get("newUsername")
            new_password = body.get("newPassword")
            if not isinstance(current_password, str):
                raise ValueError("Enter your current password to save account changes.")
            if new_username is not None and not isinstance(new_username, str):
                raise ValueError("Enter a valid account name.")
            if new_password is not None and not isinstance(new_password, str):
                raise ValueError("Enter a valid new password.")

            with _auth_lock:
                credentials = load_credentials()
                if credentials is None:
                    json_response(self, 409, {"error": "Create your local account first."})
                    return
                current_hash = password_hash(current_password, bytes.fromhex(credentials["salt"]))
                if not hmac.compare_digest(current_hash, credentials["password_hash"]):
                    json_response(self, 400, {"error": "Current password is incorrect."})
                    return

                username = credentials["username"]
                if new_username is not None and new_username.strip():
                    username = new_username.strip().casefold()
                    if (
                        len(username) < 3 or len(username) > 64
                        or any(ord(character) < 32 for character in username)
                    ):
                        raise ValueError("Account name must be 3–64 characters.")
                password_changed = bool(new_password)
                if password_changed and (len(new_password) < 12 or len(new_password) > 256):
                    raise ValueError("New password must be between 12 and 256 characters.")
                if username == credentials["username"] and not password_changed:
                    raise ValueError("Enter a new account name or a new password.")

                credentials["username"] = username
                if password_changed:
                    update_password(credentials, new_password)
                write_credentials(credentials)
                if password_changed:
                    with _recovery_lock:
                        _pending_password_resets.clear()

            active_token = self.session_token()
            with _sessions_lock:
                for token in list(_sessions):
                    if token != active_token:
                        _sessions.pop(token, None)
            json_response(self, 200, {"username": username})
        except RuntimeError as exc:
            json_response(self, 500, {"error": str(exc)})
        except (OSError, TypeError, ValueError) as exc:
            json_response(self, 400, {"error": str(exc)})

    def handle_recovery_email_verify(self):
        try:
            body = self.read_json_body()
            if not isinstance(body, dict):
                raise ValueError("Invalid email recovery settings.")
            email = body.get("email")
            if not valid_email_address(email):
                raise ValueError("Enter a valid recovery email address.")
            email = email.strip()

            with _auth_lock:
                credentials = load_credentials()
                if credentials is None:
                    json_response(self, 409, {"error": "Create your local account first."})
                    return
                smtp_settings = make_smtp_settings(body, credentials)
                candidate = dict(credentials)
                candidate.update(smtp_settings)

            session_token = self.session_token()
            now = time()
            with _recovery_lock:
                previous_request = _last_verification_request.get(session_token, 0)
                if now - previous_request < RECOVERY_REQUEST_COOLDOWN_SECONDS:
                    json_response(self, 429, {"error": "Wait one minute before requesting another verification email."})
                    return
                _last_verification_request[session_token] = now

            code = "%06d" % secrets.randbelow(1_000_000)
            send_account_email(
                candidate,
                email,
                "Verify your Frame Studio recovery email",
                "Your Frame Studio verification code is %s.\n\n"
                "Enter this code in the account settings within 10 minutes. "
                "If you did not request this, you can ignore this message." % code,
            )

            with _auth_lock:
                latest = load_credentials()
                if latest is None:
                    json_response(self, 409, {"error": "Create your local account first."})
                    return
                latest.update(smtp_settings)
                write_credentials(latest)

            salt = secrets.token_bytes(16)
            verification = {
                "email": email,
                "salt": salt.hex(),
                "code_hash": hashlib.sha256(salt + code.encode("ascii")).hexdigest(),
                "expires_at": time() + RECOVERY_CODE_TTL_SECONDS,
                "attempts": 0,
            }
            with _recovery_lock:
                _pending_email_verifications[session_token] = verification
        except (OSError, RuntimeError, smtplib.SMTPException, TypeError, ValueError) as exc:
            json_response(self, 400, {"error": "Could not send verification email: %s" % exc})
            return

        json_response(self, 200, {"verificationSent": True})

    def handle_recovery_email_confirm(self):
        try:
            body = self.read_json_body()
            code = body.get("code") if isinstance(body, dict) else None
            if not isinstance(code, str) or not code.isdigit() or len(code) != 6:
                raise ValueError("Enter the six-digit verification code.")
            token = self.session_token()

            with _auth_lock:
                with _recovery_lock:
                    pending = _pending_email_verifications.get(token)
                    if pending is None or pending["expires_at"] <= time():
                        _pending_email_verifications.pop(token, None)
                        raise ValueError("The verification code is invalid or expired.")
                    if pending["attempts"] >= 5:
                        _pending_email_verifications.pop(token, None)
                        raise ValueError("Too many attempts. Send a new verification code.")
                    pending["attempts"] += 1
                    supplied_hash = hashlib.sha256(
                        bytes.fromhex(pending["salt"]) + code.encode("ascii")
                    ).hexdigest()
                    if not hmac.compare_digest(supplied_hash, pending["code_hash"]):
                        raise ValueError("The verification code is incorrect.")

                    credentials = load_credentials()
                    if credentials is None:
                        json_response(self, 409, {"error": "Create your local account first."})
                        return
                    if credentials.get("recovery_email", "").casefold() != pending["email"].casefold():
                        _pending_password_resets.clear()
                    credentials["recovery_email"] = pending["email"]
                    credentials["recovery_verified"] = True
                    write_credentials(credentials)
                    _pending_email_verifications.pop(token, None)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            json_response(self, 400, {"error": str(exc)})
            return

        json_response(self, 200, {"recoveryVerified": True})

    def handle_password_reset_request(self):
        try:
            body = self.read_json_body()
            email = body.get("email") if isinstance(body, dict) else None
            if not valid_email_address(email):
                raise ValueError("Enter a valid recovery email address.")
        except (TypeError, ValueError) as exc:
            json_response(self, 400, {"error": str(exc)})
            return

        generic_response = {
            "message": "If the address is registered and email is working, a reset token will arrive shortly. Check your inbox and verify SMTP settings if it does not."
        }
        remote = self.client_address[0]
        now = time()
        with _recovery_lock:
            previous_request = _last_recovery_request.get(remote, 0)
            if now - previous_request < RECOVERY_REQUEST_COOLDOWN_SECONDS:
                json_response(self, 200, generic_response)
                return
            _last_recovery_request[remote] = now

        try:
            credentials = load_credentials()
            if (
                credentials is not None
                and credentials.get("recovery_verified") is True
                and credentials.get("recovery_email", "").casefold() == email.strip().casefold()
            ):
                token = secrets.token_urlsafe(32)
                send_account_email(
                    credentials,
                    credentials["recovery_email"],
                    "Frame Studio password reset",
                    "Use this one-time reset token in Frame Studio:\n\n%s\n\n"
                    "It expires in 30 minutes; keep Frame Studio running while you use it. "
                    "If you did not request this, ignore this email."
                    % token,
                )
                token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
                with _recovery_lock:
                    for existing_hash, pending in list(_pending_password_resets.items()):
                        if pending["email"].casefold() == email.strip().casefold():
                            _pending_password_resets.pop(existing_hash, None)
                    _pending_password_resets[token_hash] = {
                        "email": email.strip(),
                        "expires_at": time() + PASSWORD_RESET_TTL_SECONDS,
                    }
        except (OSError, RuntimeError, smtplib.SMTPException, TypeError, ValueError) as exc:
            print("Password recovery email could not be sent: %s" % exc)

        json_response(self, 200, generic_response)

    def handle_password_reset(self):
        try:
            body = self.read_json_body()
            token = body.get("token") if isinstance(body, dict) else None
            password = body.get("password") if isinstance(body, dict) else None
            if not isinstance(token, str) or not token or len(token) > 256:
                raise ValueError("Enter the reset token from your email.")
            if not isinstance(password, str) or len(password) < 12 or len(password) > 256:
                raise ValueError("New password must be between 12 and 256 characters.")
            token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()

            with _auth_lock:
                with _recovery_lock:
                    pending = _pending_password_resets.pop(token_hash, None)
                    if pending is None or pending["expires_at"] <= time():
                        raise ValueError("The reset token is invalid or expired.")
                    credentials = load_credentials()
                    if credentials is None:
                        json_response(self, 409, {"error": "Create your local account first."})
                        return
                    update_password(credentials, password)
                    write_credentials(credentials)
                    _pending_password_resets.clear()
                    _pending_email_verifications.clear()
                with _sessions_lock:
                    _sessions.clear()
        except (OSError, RuntimeError, TypeError, ValueError, UnicodeError) as exc:
            json_response(self, 400, {"error": str(exc)})
            return

        json_response(self, 200, {"passwordReset": True})

    def handle_auth_setup(self):
        try:
            body = self.read_json_body()
            if not isinstance(body, dict):
                raise ValueError("Invalid account setup request.")
            username = body.get("username")
            password = body.get("password")
            if not isinstance(username, str) or not isinstance(password, str):
                raise ValueError("Enter a username and password.")
            username = username.strip().casefold()
            if (
                len(username) < 3 or len(username) > 64
                or any(ord(character) < 32 for character in username)
            ):
                raise ValueError("Username must be 3–64 characters.")
            if len(password) < 12 or len(password) > 256:
                raise ValueError("Password must be between 12 and 256 characters.")
            with _auth_lock:
                if AUTH_FILE.exists():
                    json_response(self, 409, {"error": "An account already exists. Sign in instead."})
                    return
                save_credentials(username, password)
        except (OSError, TypeError, ValueError) as exc:
            json_response(self, 400, {"error": str(exc)})
            return

        json_response(self, 200, {"authenticated": True}, self.create_session())

    def handle_auth_login(self):
        try:
            body = self.read_json_body()
            if not isinstance(body, dict):
                raise ValueError("Invalid sign-in request.")
            username = body.get("username")
            password = body.get("password")
            if not isinstance(username, str) or not isinstance(password, str):
                raise ValueError("Enter your username and password.")
            credentials = load_credentials()
            if credentials is None:
                json_response(self, 409, {"error": "Create your local account first."})
                return
            salt = bytes.fromhex(credentials["salt"])
            supplied_hash = password_hash(password, salt)
        except RuntimeError as exc:
            json_response(self, 500, {"error": str(exc)})
            return
        except (TypeError, ValueError) as exc:
            json_response(self, 400, {"error": str(exc)})
            return

        valid = (
            hmac.compare_digest(username.strip().casefold(), credentials["username"])
            and hmac.compare_digest(supplied_hash, credentials["password_hash"])
        )
        if not valid:
            json_response(self, 401, {"error": "Username or password is incorrect."})
            return
        json_response(self, 200, {"authenticated": True}, self.create_session())

    def handle_auth_logout(self):
        json_response(self, 200, {"authenticated": False}, self.clear_session())

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/":
            self.serve_static(STATIC_DIR / "index.html")
            return

        if parsed.path == "/api/auth/status":
            self.handle_auth_status()
            return

        if parsed.path.startswith("/api/") and not self.is_authenticated():
            json_response(self, 401, {"error": "Sign in to access your image library."})
            return

        if parsed.path == "/api/auth/account":
            self.handle_auth_account()
            return

        if parsed.path == "/api/images":
            query = parse_qs(parsed.query)
            directory = safe_directory(query.get("directory", [str(UPLOAD_DIR)])[0])
            if directory is None:
                json_response(self, 400, {"error": "Directory does not exist."})
                return

            try:
                paths = [
                    path for path in sorted(directory.iterdir(), key=lambda item: item.name.lower())
                    if path.is_file() and path.suffix.lower() in IMAGE_EXTENSIONS
                ]
                groups = group_images(paths)
            except OSError as exc:
                json_response(self, 500, {"error": str(exc)})
                return

            json_response(self, 200, {
                "directory": str(directory),
                "groups": groups,
            })
            return

        if parsed.path == "/api/download":
            query = parse_qs(parsed.query)
            directory = safe_directory(query.get("directory", [None])[0])
            upload_root = UPLOAD_DIR.resolve()
            if directory is None or directory != upload_root:
                json_response(self, 400, {"error": "Only uploaded images can be downloaded."})
                return

            try:
                paths = [
                    path for path in sorted(directory.iterdir(), key=lambda item: item.name.lower())
                    if path.is_file() and path.suffix.lower() in IMAGE_EXTENSIONS
                ]
                if not paths:
                    json_response(self, 404, {"error": "There are no images to download."})
                    return

                with tempfile.SpooledTemporaryFile(max_size=32 * 1024 * 1024, mode="w+b") as archive_file:
                    with zipfile.ZipFile(archive_file, "w", compression=zipfile.ZIP_STORED) as archive:
                        for path in paths:
                            archive.write(path, arcname=path.name)
                    archive_file.seek(0, io.SEEK_END)
                    archive_size = archive_file.tell()
                    archive_file.seek(0)

                    self.send_response(200)
                    self.send_header("Content-Type", "application/zip")
                    self.send_header("Content-Length", str(archive_size))
                    self.send_header("Content-Disposition", 'attachment; filename="original-images.zip"')
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    shutil.copyfileobj(archive_file, self.wfile)
            except OSError as exc:
                json_response(self, 500, {"error": "Could not create download: %s" % exc})
            return

        if parsed.path == "/api/file":
            query = parse_qs(parsed.query)
            raw_path = query.get("path", [""])[0]
            path = Path(unquote(raw_path)).expanduser()
            if not path.is_absolute():
                path = Path.cwd() / path
            try:
                path = path.resolve(strict=True)
            except (OSError, RuntimeError):
                json_response(self, 404, {"error": "File not found."})
                return

            if not path.is_file() or path.suffix.lower() not in IMAGE_EXTENSIONS:
                json_response(self, 404, {"error": "File not found."})
                return

            self.send_response(200)
            mime_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(path.stat().st_size))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            with path.open("rb") as file:
                shutil.copyfileobj(file, self.wfile)
            return

        self.serve_static(STATIC_DIR / parsed.path.lstrip("/"))

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/auth/setup":
            self.handle_auth_setup()
            return
        if parsed.path == "/api/auth/login":
            self.handle_auth_login()
            return
        if parsed.path == "/api/auth/logout":
            self.handle_auth_logout()
            return
        if parsed.path == "/api/auth/recovery/request":
            self.handle_password_reset_request()
            return
        if parsed.path == "/api/auth/recovery/reset":
            self.handle_password_reset()
            return

        if parsed.path.startswith("/api/") and not self.is_authenticated():
            json_response(self, 401, {"error": "Sign in to access your image library."})
            return

        if parsed.path == "/api/auth/account":
            self.handle_auth_account_update()
            return
        if parsed.path == "/api/auth/recovery/email/verify":
            self.handle_recovery_email_verify()
            return
        if parsed.path == "/api/auth/recovery/email/confirm":
            self.handle_recovery_email_confirm()
            return
        if parsed.path == "/api/upload":
            self.handle_upload()
            return
        if parsed.path == "/api/edit":
            self.handle_edit()
            return
        if parsed.path == "/api/pdf":
            self.handle_pdf()
            return
        if parsed.path == "/api/document":
            self.handle_document()
            return
        if parsed.path == "/api/delete":
            self.handle_delete()
            return
        if parsed.path == "/api/download-selected":
            self.handle_download_selected()
            return

        if parsed.path != "/api/move":
            json_response(self, 404, {"error": "Endpoint not found."})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            source = Path(body["source"]).expanduser().resolve(strict=True)
            destination_dir = Path(body["destination"]).expanduser().resolve()
        except (json.JSONDecodeError, KeyError, OSError, RuntimeError, TypeError):
            json_response(self, 400, {"error": "Invalid source or destination."})
            return

        if not source.is_file() or source.suffix.lower() not in IMAGE_EXTENSIONS:
            json_response(self, 400, {"error": "Source is not an image."})
            return

        try:
            destination_dir.mkdir(parents=True, exist_ok=True)
            destination = destination_dir / source.name

            if destination.exists():
                stem, suffix = source.stem, source.suffix
                counter = 1
                while destination.exists():
                    destination = destination_dir / ("%s_%d%s" % (stem, counter, suffix))
                    counter += 1

            shutil.move(str(source), str(destination))
        except OSError as exc:
            json_response(self, 500, {"error": str(exc)})
            return

        json_response(self, 200, {"movedTo": str(destination)})

    def handle_upload(self):
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("multipart/form-data;"):
            json_response(self, 400, {"error": "Expected a multipart file upload."})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            json_response(self, 400, {"error": "Invalid upload size."})
            return
        if length <= 0 or length > MAX_UPLOAD_SIZE:
            json_response(self, 413, {"error": "Upload is empty or exceeds the 512 MB limit."})
            return

        try:
            body = self.rfile.read(length)
            message = BytesParser(policy=policy.default).parsebytes(
                b"Content-Type: " + content_type.encode("ascii") +
                b"\r\nMIME-Version: 1.0\r\n\r\n" + body
            )
            parts = list(message.iter_parts())
            UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
            uploaded = 0

            for part in parts:
                filename = part.get_filename()
                if not filename:
                    continue
                name = Path(filename.replace("\\", "/")).name
                if not name or Path(name).suffix.lower() not in IMAGE_EXTENSIONS:
                    continue

                destination = UPLOAD_DIR / name
                if destination.exists():
                    destination = UPLOAD_DIR / ("%s_%d%s" % (
                        Path(name).stem, time_ns(), Path(name).suffix
                    ))
                destination.write_bytes(part.get_payload(decode=True) or b"")
                uploaded += 1

            if not uploaded:
                json_response(self, 400, {"error": "No supported image files were selected."})
                return
        except (OSError, ValueError, UnicodeError) as exc:
            json_response(self, 500, {"error": "Could not save uploaded images: %s" % exc})
            return

        json_response(self, 200, {
            "directory": str(UPLOAD_DIR.resolve()),
            "uploaded": uploaded,
        })

    def handle_delete(self):
        try:
            body = self.read_json_body()
            filenames = body.get("filenames") if isinstance(body, dict) else None
            if (
                not isinstance(filenames, list) or not filenames
                or len(filenames) > 200
                or any(not isinstance(filename, str) or not filename for filename in filenames)
            ):
                raise ValueError("Select between 1 and 200 uploaded images to delete.")
        except (TypeError, ValueError) as exc:
            json_response(self, 400, {"error": str(exc)})
            return

        deleted = []
        failed = []
        for filename in dict.fromkeys(filenames):
            try:
                path = uploaded_image(filename)
                path.unlink()
                deleted.append(filename)
            except (OSError, ValueError) as exc:
                failed.append({"filename": filename, "error": str(exc)})

        if failed:
            json_response(self, 207 if deleted else 500, {
                "deleted": deleted,
                "failed": failed,
                "error": "Some selected images could not be deleted.",
            })
            return
        json_response(self, 200, {"deleted": deleted, "failed": []})

    def handle_download_selected(self):
        try:
            body = self.read_json_body()
            filenames = body.get("filenames") if isinstance(body, dict) else None
            if (
                not isinstance(filenames, list) or not filenames
                or len(filenames) > 200
                or any(not isinstance(filename, str) or not filename for filename in filenames)
            ):
                raise ValueError("Select between 1 and 200 images to download.")
            paths = [uploaded_image(filename) for filename in dict.fromkeys(filenames)]
            if not paths:
                raise ValueError("Select at least one uploaded image.")

            with tempfile.SpooledTemporaryFile(max_size=32 * 1024 * 1024, mode="w+b") as archive_file:
                with zipfile.ZipFile(archive_file, "w", compression=zipfile.ZIP_STORED) as archive:
                    for path in paths:
                        archive.write(path, arcname=path.name)
                archive_file.seek(0, io.SEEK_END)
                archive_size = archive_file.tell()
                archive_file.seek(0)

                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Length", str(archive_size))
                self.send_header("Content-Disposition", 'attachment; filename="selected-images.zip"')
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                shutil.copyfileobj(archive_file, self.wfile)
        except (OSError, TypeError, ValueError) as exc:
            json_response(self, 400, {"error": str(exc)})

    def read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid request size.") from exc
        if length <= 0 or length > 1024 * 1024:
            raise ValueError("Request is empty or too large.")
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise ValueError("Invalid JSON request.") from exc

    def send_download(self, data, filename, content_type):
        from urllib.parse import quote

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header(
            "Content-Disposition",
            "attachment; filename*=UTF-8''%s" % quote(filename),
        )
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def handle_edit(self):
        try:
            body = self.read_json_body()
            if not isinstance(body, dict):
                raise ValueError("Invalid edit request.")
            data, filename, content_type = edited_image(body)
        except BackgroundRemovalError as exc:
            json_response(self, 503, {"error": str(exc)})
            return
        except (KeyError, OSError, TypeError, ValueError, Image.DecompressionBombError) as exc:
            json_response(self, 400, {"error": str(exc)})
            return
        self.send_download(data, filename, content_type)

    def handle_pdf(self):
        pdf = None
        try:
            import pymupdf

            body = self.read_json_body()
            filenames = body.get("filenames") if isinstance(body, dict) else None
            if (
                not isinstance(filenames, list) or not filenames
                or len(filenames) > 200
            ):
                raise ValueError("Select between 1 and 200 images for the PDF.")

            pdf = pymupdf.open()
            for filename in filenames:
                path = uploaded_image(filename)
                with Image.open(path) as source:
                    image = ImageOps.exif_transpose(source)
                    image.load()
                    if image.mode == "RGBA":
                        background = Image.new("RGB", image.size, "white")
                        background.paste(image, mask=image.getchannel("A"))
                        image = background
                    elif image.mode != "RGB":
                        image = image.convert("RGB")
                    page_data = io.BytesIO()
                    image.save(
                        page_data,
                        format="PDF",
                        resolution=300,
                        quality=100,
                        subsampling=0,
                    )
                page = pymupdf.open(stream=page_data.getvalue(), filetype="pdf")
                try:
                    pdf.insert_pdf(page)
                finally:
                    page.close()
            data = pdf.tobytes(garbage=4, deflate=True)
        except (KeyError, OSError, TypeError, ValueError, Image.DecompressionBombError) as exc:
            json_response(self, 400, {"error": str(exc)})
            return
        except Exception as exc:
            json_response(self, 500, {"error": "Could not create PDF: %s" % exc})
            return
        finally:
            if pdf is not None:
                pdf.close()
        self.send_download(data, "image-collection.pdf", "application/pdf")

    def handle_document(self):
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("multipart/form-data;"):
            json_response(self, 400, {"error": "Choose one PDF, DOC, or DOCX file."})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            json_response(self, 400, {"error": "Invalid document size."})
            return
        if length <= 0 or length > MAX_DOCUMENT_SIZE:
            json_response(self, 413, {"error": "Document is empty or exceeds the 128 MB limit."})
            return

        try:
            body = self.rfile.read(length)
            message = BytesParser(policy=policy.default).parsebytes(
                b"Content-Type: " + content_type.encode("ascii") +
                b"\r\nMIME-Version: 1.0\r\n\r\n" + body
            )
            file_parts = [part for part in message.iter_parts() if part.get_filename()]
            if len(file_parts) != 1:
                raise ValueError("Choose exactly one PDF, DOC, or DOCX file.")

            file_part = file_parts[0]
            filename = Path(file_part.get_filename().replace("\\", "/")).name
            extension = Path(filename).suffix.lower()
            if extension not in DOCUMENT_EXTENSIONS:
                raise ValueError("Choose a PDF, DOC, or DOCX file.")
            output_format = next(
                (
                    part.get_content().strip().lower()
                    for part in message.iter_parts()
                    if part.get_param("name", header="content-disposition") == "format"
                ),
                "",
            )

            with tempfile.TemporaryDirectory(prefix="frame-studio-document-") as directory:
                source_path = Path(directory) / ("source" + extension)
                output_path = Path(directory) / ("converted." + output_format)
                source_path.write_bytes(file_part.get_payload(decode=True) or b"")
                convert_document(source_path, output_path, output_format)
                data = output_path.read_bytes()

            output_name = Path(filename).stem + "." + output_format
            content_type = (
                "application/pdf"
                if output_format == "pdf"
                else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            )
        except DocumentConversionError as exc:
            json_response(self, 503, {"error": str(exc)})
            return
        except (OSError, TypeError, ValueError, UnicodeError) as exc:
            json_response(self, 400, {"error": str(exc)})
            return

        self.send_download(data, output_name, content_type)

    def serve_static(self, path):
        try:
            path = path.resolve(strict=True)
            if path != STATIC_DIR.resolve() and STATIC_DIR.resolve() not in path.parents:
                json_response(self, 403, {"error": "Forbidden."})
                return
            if not path.is_file():
                raise FileNotFoundError
            data = path.read_bytes()
        except (OSError, RuntimeError):
            json_response(self, 404, {"error": "Not found."})
            return

        mime_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", mime_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


def main():
    server = ThreadingHTTPServer((HOST, PORT), ImageSorterHandler)
    print("Image Sorter running at http://%s:%d" % (HOST, PORT))
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()