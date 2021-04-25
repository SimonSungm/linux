$(foreach config,$(filter CONFIG_%, $(.VARIABLES)), $(eval undefine $(config)))
CONFIG_TRACE_ERROR=y
CONFIG_CRASH_CELL_ON_PANIC=y
CONFIG_TEST_DEVICE=y
