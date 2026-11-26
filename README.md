# Frame Studio

Frame Studio is a local-first Windows application for organizing photo libraries, finding visually similar images, editing photos, and exporting images and documents. It runs on your computer: uploaded images and editing operations stay local rather than being sent to a hosted image service.

## What Frame Studio does

### Organize and find similar photos

- Add individual images or import a folder into the Library.
- Browse and search your imported images, or review automatically grouped lookalikes in Duplicates. Grouping uses perceptual image hashes; it identifies visual similarity, not exact file equality.
- Select individual or multiple photos to download or delete. Deletion requires confirmation; Clear library is a separate action.
- Download originals without recompressing or overwriting them.

Supported image inputs include JPEG, PNG, GIF, BMP, WebP, TIFF, and HEIC, subject to the installed image-decoding support.

### Edit and export images

- View the original and live edited preview side by side.
- Crop freely or use a preset aspect ratio; resize to chosen pixel dimensions.
- Adjust brightness, contrast, saturation, color temperature, sharpness, and blur; apply a filter.
- Optionally remove a background with the local U²-Net model.
- Export edits as JPEG, PNG, WebP, TIFF, BMP, or PDF. The original image remains unchanged.
- Download selected images together as a ZIP, download all originals, or create a PDF from the images currently shown.

### Work with PDF and Word documents

- Convert PDF files to editable DOCX files locally.
- Convert DOC or DOCX files to PDF using Microsoft Word installed on the computer.
- Export a PDF with one page per image from the Library or Duplicates view.

PDF-to-DOCX conversion does not perform OCR. Scanned PDFs need OCR before their text can be edited, and complex layouts may need cleanup after conversion. For Google Docs, download the document as DOCX before converting.

### Account and interface

- Set up a local account, change the account name or password, and optionally configure email-based password recovery.
- Use the interface in light or dark mode.

## Requirements

- Windows
- Python 3.13
- [uv](https://docs.astral.sh/uv/) for the setup commands below
- Microsoft Word installed for DOC/DOCX-to-PDF conversion

Frame Studio uses Python's built-in HTTP server, Pillow for image processing, `rembg` for local background removal, and `pdf2docx` for PDF-to-DOCX conversion. The first background-removal request may download the U²-Net model into the local `Models` directory; the model is not included in this repository.

## Run Frame Studio

From the project directory, create the environment, install dependencies, and start the app:

```powershell
uv venv --python 3.13 .venv
uv pip install --python .venv\Scripts\python.exe -r requirements.txt
.\run.bat
```

Alternatively, open `run.bat` in File Explorer after setup. Keep its console window open while using the app. Then visit [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser. On first launch, create the local account and password.

## Local data and privacy

- The application binds to `127.0.0.1` and is intended for use on the same computer. Do not expose it to a network or the public internet without a separate security review and deployment design.
- Imported images are stored in the project's `Uploads` directory. They are intentionally excluded from Git.
- The optional background-removal model is stored under `Models` and is also excluded from Git.
- Account settings are stored under `%LOCALAPPDATA%\FrameStudio`, outside the project directory.
- Password recovery is optional and requires configuring an SMTP provider and verifying the recovery email address.

## Project files

```text
main.py               Local HTTP server, authentication, image and document processing
Static/index.html     Frame Studio interface
Static/favicon.svg    App icon
requirements.txt      Python dependencies
run.bat               Windows launcher
```

## License

No open-source license is currently included. All rights are reserved unless the project owner adds a license.
