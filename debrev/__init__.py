"""debrev: Debian reverse proxy manager."""
__version__ = "0.1.0"
# Bump when the on-disk state layout changes; used later to let twin nodes
# on different app versions refuse incompatible syncs.
STATE_FORMAT = 1
