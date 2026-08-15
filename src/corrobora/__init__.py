"""Corrobora's artifact parsers and correlation engine.

Each artifact parser (``evtx``, ``registry``, ``prefetch``, ``mft``)
is independently importable and usable on its own. ``correlation_engine``
cross-references their output; ``case_ingest`` auto-discovers artifact
files in a folder or zip archive; ``corrobora_gui`` is the desktop
interface tying everything together.
"""