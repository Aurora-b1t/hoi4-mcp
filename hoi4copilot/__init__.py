"""hoi4-copilot: let an external agent play Hearts of Iron IV via an MCP server.

Reads game state straight from the process (never pausing it) and executes
actions through the game's own player command queue (the same path mouse
clicks take) - no console cheats, no illegal value writes.
"""

__version__ = "0.1.0"

# The table generation pins one exact game build; if Steam updates HOI4 the
# offset tables must be regenerated before the server will attach again.
SUPPORTED_VERSION = "1.19.3.0"
SUPPORTED_CHECKSUM = "5632"
