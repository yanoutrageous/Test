from __future__ import annotations


class PageRangeError(ValueError):
    """Raised when a page selection string cannot be parsed."""


def parse_page_numbers(
    value: str | None,
    *,
    default: tuple[int, ...] | None = None,
) -> tuple[int, ...]:
    if value is None or not value.strip():
        if default is not None:
            return tuple(default)
        raise PageRangeError("At least one page number is required.")

    pages: list[int] = []
    seen: set[int] = set()
    for part in value.replace(";", ",").split(","):
        text = part.strip()
        if not text:
            continue

        if "-" in text:
            numbers = _parse_range(text)
        else:
            numbers = (_parse_positive_int(text, original=text),)

        for page_no in numbers:
            if page_no not in seen:
                pages.append(page_no)
                seen.add(page_no)

    if not pages:
        raise PageRangeError("At least one page number is required.")

    return tuple(pages)


def format_page_spec(pages: tuple[int, ...] | list[int]) -> str:
    """Return a compact, stable page range string for already parsed pages."""
    if not pages:
        return ""

    sorted_pages = sorted(dict.fromkeys(int(page_no) for page_no in pages))
    ranges: list[str] = []
    start = sorted_pages[0]
    previous = sorted_pages[0]
    for page_no in sorted_pages[1:]:
        if page_no == previous + 1:
            previous = page_no
            continue
        ranges.append(f"{start}-{previous}" if start != previous else str(start))
        start = previous = page_no
    ranges.append(f"{start}-{previous}" if start != previous else str(start))
    return ",".join(ranges)


def _parse_range(text: str) -> range:
    parts = [part.strip() for part in text.split("-")]
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise PageRangeError(f"Invalid page range: {text}")

    start = _parse_positive_int(parts[0], original=text)
    end = _parse_positive_int(parts[1], original=text)
    if start > end:
        raise PageRangeError(f"Page range start must be <= end: {text}")

    return range(start, end + 1)


def _parse_positive_int(text: str, *, original: str) -> int:
    try:
        page_no = int(text)
    except ValueError as exc:
        raise PageRangeError(f"Invalid page number: {original}") from exc
    if page_no < 1:
        raise PageRangeError(f"Page numbers must be positive: {page_no}")
    return page_no
