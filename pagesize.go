package auth

// WithDefaultPageSize sets how many rows a list returns when the caller asks
// for no particular number, across every list that reads it (PageSize), as
// better-auth's advanced.database.defaultFindManyLimit caps findMany. It
// changes only the default: each list keeps its own maximum, so the option
// can make a list answer fewer rows by default but never more than the list
// allows. New refuses a negative value; 0 keeps each list's own default.
//
//ds:def id=opt-withdefaultpagesize-3kd8wq2n owner=@khanakia stability=stable
func WithDefaultPageSize(n int) Option { return func(s *settings) { s.cfg.DefaultPageSize = n } }

// PageSize is the number of rows a list answers: requested when it is
// positive and at most limit; limit when requested is larger; and with no
// request (0 or less), WithDefaultPageSize when set, else fallback, the
// list's own default, both capped at limit. A list calls it with its own
// fallback and limit, so one rule decides every list's size.
func (c Config) PageSize(requested, fallback, limit int) int {
	n := requested
	if n <= 0 {
		n = fallback
		if c.DefaultPageSize > 0 {
			n = c.DefaultPageSize
		}
	}
	return min(n, limit)
}
