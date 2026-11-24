"""Lecteur de documents — extrait le texte d'un PDF, Word ou fichier texte.

Le texte extrait alimente ensuite l'extracteur IA (comme si le consultant
l'avait tapé). Pour l'instant : documents ÉCRITS (PDF / DOCX / TXT). Les
captures d'écran, schémas, logs et audio viendront plus tard.
"""

import io


def read_pdf(data: bytes) -> str:
    import pdfplumber
    parts = []
    with pdfplumber.open(io.BytesIO(data)) as pdf:
        for page in pdf.pages:
            t = page.extract_text()
            if t:
                parts.append(t)
    return "\n".join(parts)


def read_docx(data: bytes) -> str:
    import docx
    doc = docx.Document(io.BytesIO(data))
    return "\n".join(p.text for p in doc.paragraphs if p.text.strip())


def read_txt(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def read_document(filename: str, data: bytes) -> str:
    """Aiguille selon l'extension. Renvoie le texte, ou lève si format non géré."""
    name = (filename or "").lower()
    if name.endswith(".pdf"):
        return read_pdf(data)
    if name.endswith(".docx"):
        return read_docx(data)
    if name.endswith((".txt", ".md", ".csv", ".log")):
        return read_txt(data)
    raise ValueError(f"Format non supporté : {filename}. Formats acceptés : PDF, DOCX, TXT.")
