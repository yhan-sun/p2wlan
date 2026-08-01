package api

import "strconv"

func fmtInt64(value int64) string {
	return strconv.FormatInt(value, 10)
}
