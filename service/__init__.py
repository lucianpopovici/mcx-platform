"""Host process for the platform.

Everything that touches a socket, a file, a database or the wall clock lives
here; `core/` stays free of all four. This package may import `core`; `core`
never imports it.
"""
