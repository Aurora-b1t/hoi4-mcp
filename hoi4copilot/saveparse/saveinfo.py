"""Fast save header reader: parse the first few KB of a HOI4bin5 save and
decode the standard header fields (player, date, difficulty, version...).

Date encoding solved empirically (GER/ITA saves):
    date_token = 60759359 + game hours since 1936-01-01 00:00
So: absolute_hour = date_token - 60759359; hour-of-day = abs % 24 and the day
count follows standard month lengths starting at 1936-01-01.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import bin5

DATE_EPOCH = 60759359        # token value == hours since 1936-01-01 00:00
T_IDEOLOGY = 0x2E3E
T_DIFFICULTY = 0x299F
T_VERSION = 0x00EE
T_DATE = 0x284A


def _month_lengths(y: int) -> list[int]:
    # HOI4 calendar: every year is a standard 365-day year (no leap days)
    return [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]


def decode_date(token: int) -> str:
    """date token -> 'YYYY-MM-DD hh' (raw fallback for absurd values)."""
    abs_hours = token - DATE_EPOCH
    if abs(abs_hours) > 24 * 366 * 2000:
        return f"{token} (raw)"
    backward = abs_hours < 0
    day, hour = divmod(abs_hours, 24)
    if hour < 0:
        hour += 24
        day -= 1
    day = abs(day)
    y = 1936
    if backward:
        # walk back to < 1936
        while day >= sum(_month_lengths(y - 1)):
            day -= sum(_month_lengths(y - 1))
            y -= 1
    else:
        while True:
            ml = _month_lengths(y)
            if day < sum(ml):
                break
            day -= sum(ml)
            y += 1
    d = 0
    while day >= _month_lengths(y)[d]:
        day -= _month_lengths(y)[d]
        d += 1
    return f"{y:04d}-{d + 1:02d}-{day + 1:02d} {hour:02d}"


def encode_date(y: int, m: int, d: int, h: int = 0) -> int:
    """Inverse of decode_date (for building expected tokens / probes)."""
    days = 0
    for yy in range(1936, y):
        days += sum(_month_lengths(yy))
    ml = _month_lengths(y)
    days += sum(ml[:m - 1]) + (d - 1)
    return DATE_EPOCH + days * 24 + h


@dataclass
class SaveHeader:
    path: Path
    pairs: list
    name_map: dict = field(default_factory=dict)

    def get(self, key, default=None):
        for k, v, _ in self.pairs:
            if k == key:
                return v
        return default

    def player(self) -> str | None:
        v = self.pairs[0][1] if self.pairs else None
        return v if isinstance(v, str) else None

    def date_token(self) -> int | None:
        v = self.get(T_DATE)
        return v if isinstance(v, int) else None

    def date_str(self) -> str:
        t = self.date_token()
        return decode_date(t) if t is not None else "?"

    def summary(self) -> str:
        player = self.player() or "?"
        ideo = self.get(T_IDEOLOGY)
        diff = self.get(T_DIFFICULTY)
        return (f"{self.path.name}: player={player} "
                f"ideology={ideo!r} difficulty={diff!r} date={self.date_str()}")


def read_header(path: str | Path, name_map: dict[int, str] | None = None,
                limit: int = 65536) -> SaveHeader:
    """Parse the first `limit` bytes after the magic; the header is front-loaded."""
    if name_map is None:
        from .tokens import load_tokens
        name_map = load_tokens()
    path = Path(path)
    pairs = bin5.parse(path.read_bytes(), limit=limit)
    return SaveHeader(path=path, pairs=pairs, name_map=name_map)


if __name__ == "__main__":
    import sys

    for p in sys.argv[1:]:
        try:
            h = read_header(p)
            print(h.summary())
        except Exception as exc:
            print(f"{p}: {exc}")
