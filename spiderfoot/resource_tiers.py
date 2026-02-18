"""Resource tier definitions for ASM-NG.

Maps tier names to concrete SQLite PRAGMA values, module concurrency,
and CherryPy thread pool sizes.  Imported by db.py and sf.py so that
the mapping lives in one place.
"""

RESOURCE_TIERS = {
    'light': {
        'label': 'LIGHT',
        'description': 'Limited resources; 4-8GB RAM',
        'sqlite_cache_size': '-32000',       # ~32 MB
        'sqlite_mmap_size': '134217728',     # 128 MB
        'maxthreads': 2,
        'cherrypy_thread_pool': 10,
    },
    'medium': {
        'label': 'MEDIUM',
        'description': 'Modest resources; 16GB RAM recommended',
        'sqlite_cache_size': '-128000',      # ~128 MB
        'sqlite_mmap_size': '536870912',     # 512 MB
        'maxthreads': 3,
        'cherrypy_thread_pool': 15,
    },
    'heavy': {
        'label': 'HEAVY',
        'description': 'Snappy/generous resources; 32GB RAM',
        'sqlite_cache_size': '-256000',      # ~256 MB
        'sqlite_mmap_size': '1073741824',    # 1 GB
        'maxthreads': 5,
        'cherrypy_thread_pool': 20,
    },
}

DEFAULT_TIER = 'medium'


def get_tier_config(tier_name):
    """Return the config dict for a tier, falling back to DEFAULT_TIER."""
    return RESOURCE_TIERS.get(tier_name, RESOURCE_TIERS[DEFAULT_TIER])
