"""Headless CLI — useful for scripting and CI."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from cipherid import __version__
from cipherid.cipher import Cipher
from cipherid.engine import Engine
from cipherid.image import (
    ExtractedItem,
    backend_status,
    extract_from_image,
    is_image_path,
)


def _safe(s: str) -> str:
    """Replace characters the local console cannot render."""
    enc = (sys.stdout.encoding or "utf-8")
    return s.encode(enc, errors="replace").decode(enc, errors="replace")


def _resolve_input(text: str, ocr: bool = True) -> tuple[str, list[ExtractedItem]]:
    """If TEXT is a path to an image, extract text from it.

    Returns ``(text_to_scan, extracted_items)``. ``extracted_items`` is empty
    when the argument was plain text.
    """
    candidate = Path(text.strip("\"' "))
    if candidate.exists() and is_image_path(candidate):
        items = extract_from_image(candidate, ocr=ocr)
        if items:
            return "\n".join(i.text for i in items), items
        return "", items
    return text, []


@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="cipherid")
@click.pass_context
def main(ctx: click.Context) -> None:
    """CipherID — identify and decode CTF ciphers."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.command()
@click.argument("text")
@click.option("--flag-format", default=None, help="Flag template like 'flag{}' or a regex.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of plain text.")
@click.option("--quiet", "-q", is_flag=True, help="Quiet mode: only output flag or top candidate name.")
@click.option("--top", type=int, default=10, show_default=True, help="Limit to top N candidates.")
@click.option("--no-ocr", is_flag=True, help="When TEXT is an image, skip OCR (use only QR/barcode).")
def identify(text: str, flag_format: str | None, as_json: bool, quiet: bool, top: int, no_ocr: bool) -> None:
    """Identify the cipher used in TEXT.

    TEXT may also be a path to an image file (.png .jpg .bmp .webp .tiff ...).
    QR codes and barcodes are decoded automatically; OCR is used as a fallback
    when no codes are found.
    """
    scan_text, extracted = _resolve_input(text, ocr=not no_ocr)
    if extracted:
        for item in extracted:
            if not quiet:
                click.echo(f"[image] extracted from {item.source}: {_safe(item.text)[:120]}")
        if not scan_text:
            if not quiet:
                click.echo("(no decodable text found in image)")
            sys.exit(1)
    engine = Engine()
    result = engine.identify(scan_text, flag_format=flag_format)
    candidates = result.candidates[:top]

    if as_json:
        data = {
            "flag": result.flag,
            "extracted": [
                {"source": i.source, "text": i.text, "bbox": i.bbox} for i in extracted
            ],
            "candidates": [
                {
                    "id": c.cipher_id, "name": c.name, "category": c.category,
                    "confidence": c.confidence, "decoded": c.decoded,
                    "key": c.key, "notes": c.notes,
                }
                for c in candidates
            ],
        }
        click.echo(json.dumps(data, indent=2, ensure_ascii=False))
        return

    if quiet:
        # Quiet mode: output only the flag or the top candidate name
        if result.flag:
            click.echo(result.flag)
        elif candidates:
            click.echo(candidates[0].name)
        else:
            sys.exit(1)
        return

    if result.flag:
        click.echo(f"flag: {_safe(result.flag)}")
    click.echo(f"{'conf':>5}  {'category':<10}  name")
    click.echo("-" * 60)
    for c in candidates:
        click.echo(f"{c.confidence*100:4.0f}%  {c.category:<10}  {_safe(c.name)}")
        if c.decoded:
            preview = c.decoded[:80].replace("\n", " ")
            click.echo(f"        -> {_safe(preview)}")
        if c.notes:
            click.echo(f"        note: {_safe(c.notes)}")


@main.command()
@click.argument("text")
@click.option("--flag-format", default=None)
@click.option("--max-depth", type=int, default=5, show_default=True)
@click.option("--quiet", "-q", is_flag=True, help="Quiet mode: only output the flag or final plaintext.")
@click.option("--no-ocr", is_flag=True, help="When TEXT is an image, skip OCR.")
def auto(text: str, flag_format: str | None, max_depth: int, quiet: bool, no_ocr: bool) -> None:
    """Recursively decode TEXT until a flag pattern matches.

    TEXT may be a path to an image file; QR/barcodes/OCR are extracted first.
    """
    scan_text, extracted = _resolve_input(text, ocr=not no_ocr)
    for item in extracted:
        if not quiet:
            click.echo(f"[image] extracted from {item.source}: {_safe(item.text)[:120]}")
    if not scan_text:
        if not quiet:
            click.echo("(no decodable text)")
        sys.exit(1)
    engine = Engine()
    res = engine.auto_decode(scan_text, flag_format=flag_format, max_depth=max_depth)

    if quiet:
        if res.flag_match:
            click.echo(res.flag_match)
        else:
            click.echo(res.final_plaintext)
        return

    for step in res.chain:
        click.echo(f"-> {_safe(step.name)} ({int(step.confidence*100)}%)")
    if res.flag_match:
        click.echo(f"\nFlag found: {_safe(res.flag_match)}")
    click.echo("\nFinal:")
    click.echo(_safe(res.final_plaintext))


@main.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--no-ocr", is_flag=True, help="Skip OCR; only decode QR / barcodes.")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
def image(path: Path, no_ocr: bool, as_json: bool) -> None:
    """Extract text from PATH (QR / barcode / OCR) without running identification."""
    items = extract_from_image(path, ocr=not no_ocr)
    if as_json:
        click.echo(json.dumps(
            [{"source": i.source, "text": i.text, "bbox": i.bbox} for i in items],
            indent=2, ensure_ascii=False,
        ))
        return
    if not items:
        click.echo("(nothing decoded)")
        status = backend_status()
        missing = [k for k, v in status.items() if not v]
        if missing:
            click.echo(f"hint: missing backends -> {', '.join(missing)}")
        sys.exit(1)
    for item in items:
        click.echo(f"[{item.source}] {_safe(item.text)}")


@main.command("backends")
def backends_cmd() -> None:
    """Show which image-extraction backends are available."""
    for k, v in backend_status().items():
        click.echo(f"{k:<20} {'OK' if v else 'missing'}")


@main.command()
@click.argument("text", required=False, default="")
@click.option("--algorithm", "-a", default=None, help="Cipher/encoding algorithm id (e.g. base64, caesar).")
@click.option("--key", "-k", default=None, help="Key for algorithms that require one (e.g. Caesar shift, Vigenère key).")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON output.")
def decode(text: str, algorithm: str | None, key: str | None, as_json: bool) -> None:
    """Decode TEXT using a specified algorithm.

    Examples:

        cipherid decode "SGVsbG8=" -a base64

        cipherid decode "cixd{whvw}" -a caesar -k 3

        cipherid decode "flag{test}" -a core_values
    """
    engine = Engine()

    if not algorithm:
        click.echo("Error: --algorithm is required. Run 'cipherid encode --list-algorithms' to see available options.", err=True)
        sys.exit(1)

    if not text:
        click.echo("Error: TEXT argument is required for decoding.", err=True)
        sys.exit(1)

    result = engine.decode_one(text, algorithm, key=key)
    if result is None:
        found = any(c.id == algorithm for c in engine.ciphers)
        if found:
            click.echo(f"Error: algorithm '{algorithm}' failed to decode this input (wrong key or wrong format?).", err=True)
        else:
            click.echo(f"Error: unknown algorithm '{algorithm}'.", err=True)
        sys.exit(1)

    if as_json:
        click.echo(json.dumps({"algorithm": algorithm, "key": key, "decoded": result}, ensure_ascii=False))
        return

    click.echo(result)


@main.command("gui")
def gui_cmd() -> None:
    """Launch the graphical user interface."""
    from cipherid.gui.app import main as gui_main
    sys.exit(gui_main())


CATEGORY_LABELS = {
    "encoding": "编码类 / Encoding",
    "classical": "古典密码 / Classical",
    "chinese": "中文密码 / Chinese",
    "esoteric": "深奥语言 / Esoteric",
    "hash": "哈希 / Hash (detect only)",
    "modern": "现代密码 / Modern (detect only)",
    "token": "令牌/地址 / Token (detect only)",
}


@main.command()
@click.argument("text", required=False, default="")
@click.option("--algorithm", "-a", default=None, help="Cipher/encoding algorithm id (e.g. base64, caesar).")
@click.option("--key", "-k", default=None, help="Key for algorithms that require one (e.g. Caesar shift, Vigenère key).")
@click.option("--list-algorithms", "-l", is_flag=True, help="List all encodable algorithms by category.")
@click.option("--category", "-c", default=None, help="Filter list by category (e.g. encoding, classical, chinese).")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON output.")
def encode(text: str, algorithm: str | None, key: str | None, list_algorithms: bool, category: str | None, as_json: bool) -> None:
    """Encode TEXT using a specified algorithm.

    Examples:

        cipherid encode "Hello World" -a base64

        cipherid encode "flag{test}" -a caesar -k 3

        cipherid encode --list-algorithms

        cipherid encode --list-algorithms -c classical
    """
    engine = Engine()

    if list_algorithms:
        encodable = engine.get_encodable_ciphers()
        cats: dict[str, list[Cipher]] = {}
        for c in encodable:
            cats.setdefault(c.category, []).append(c)

        if category:
            cats = {k: v for k, v in cats.items() if k == category}

        if not cats:
            click.echo("No encodable algorithms found." if not category else f"No encodable algorithms in category: {category}")
            return

        for cat, ciphers in sorted(cats.items()):
            label = CATEGORY_LABELS.get(cat, cat)
            click.echo(f"\n{label}")
            click.echo("-" * 40)
            for c in ciphers:
                extra = ""
                if c.id in ("caesar", "affine", "vigenere"):
                    extra = "  (requires --key)"
                elif c.id == "rot13":
                    extra = "  (symmetric: encode = decode)"
                click.echo(f"  {c.id:<24} {c.name}{extra}")
        return

    if not algorithm:
        click.echo("Error: --algorithm is required. Use --list-algorithms to see available options.", err=True)
        sys.exit(1)

    if not text:
        click.echo("Error: TEXT argument is required for encoding.", err=True)
        sys.exit(1)

    result = engine.encode_one(text, algorithm, key=key)
    if result is None:
        # Check if the algorithm exists but doesn't support encode
        found = any(c.id == algorithm for c in engine.ciphers)
        if found:
            click.echo(f"Error: algorithm '{algorithm}' does not support encoding.", err=True)
        else:
            click.echo(f"Error: unknown algorithm '{algorithm}'. Use --list-algorithms to see available options.", err=True)
        sys.exit(1)

    if as_json:
        click.echo(json.dumps({"algorithm": algorithm, "key": key, "encoded": result}, ensure_ascii=False))
        return

    click.echo(result)


@main.command("config")
@click.option("--init", "init_config", is_flag=True, help="Create default cipherid.json in current directory.")
@click.option("--show", "show_config", is_flag=True, help="Show current configuration.")
def config_cmd(init_config: bool, show_config: bool) -> None:
    """View or initialize CipherID configuration."""
    from cipherid.config import get_default_config_path, load_config, write_default_config
    if init_config:
        path = write_default_config()
        click.echo(f"Config written to {path}")
        return
    config = load_config()
    data = {
        "max_depth": config.max_depth,
        "beam_width": config.beam_width,
        "min_confidence": config.min_confidence,
        "disabled_ciphers": config.disabled_ciphers,
        "flag_presets": config.flag_presets,
    }
    click.echo(json.dumps(data, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
