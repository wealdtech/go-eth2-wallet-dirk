package dirk

// Uint64ToInt64 converts a uint64 to an int64.
func Uint64ToInt64(val uint64) int64 {
	if val > 0x7fffffffffffffff {
		panic("value too large to convert to int64")
	}

	//nolint:gosec
	return int64(val)
}
