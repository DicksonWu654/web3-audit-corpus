"""Compatibility wrapper for the existing generic publisher grammar."""
from parsers.generic import parse, DESCRIPTION
from variants import legacy
VARIANTS = (legacy('nethermind', parse),)
