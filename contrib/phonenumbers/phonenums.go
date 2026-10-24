// Package phonenums normalizes and validates phone numbers with country rules
// (libphonenumber, through github.com/nyaruka/phonenumbers), so users may type
// a number the way they write it at home: "0412 345 678" in Australia,
// "(555) 010-0100" in the US.
//
// Plug it into the phone plugin:
//
//	phone.New(phone.Login(),
//		phone.WithNormalizer(phonenums.Normalizer("AU")),
//		phone.WithValidator(phonenums.Validator()))
//
// It is a separate module because the country metadata is several megabytes
// that an app accepting only "+" numbers does not need.
package phonenums

import (
	"errors"
	"fmt"

	"github.com/nyaruka/phonenumbers"
)

// ErrNotANumber is returned for input no country rule can read.
var ErrNotANumber = errors.New("phonenums: not a phone number")

// Normalizer returns a phone.WithNormalizer function. A number with "+" is
// read by its own country code; one without is read as a number of
// defaultRegion (an ISO 3166 code such as "AU"). The result is E.164.
//
//ds:def id=normalizer-nkw5gw3q
func Normalizer(defaultRegion string) func(raw string) (string, error) {
	return func(raw string) (string, error) {
		n, err := phonenumbers.Parse(raw, defaultRegion)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrNotANumber, err)
		}
		return phonenumbers.Format(n, phonenumbers.E164), nil
	}
}

// Validator returns a phone.WithValidator function that accepts only numbers
// the country's rules say can exist, which also refuses numbers that are the
// right length but in no assigned range.
//
//ds:def id=validator-t8sw739j
func Validator() func(normalized string) error {
	return func(normalized string) error {
		n, err := phonenumbers.Parse(normalized, "")
		if err != nil {
			return fmt.Errorf("%w: %v", ErrNotANumber, err)
		}
		if !phonenumbers.IsValidNumber(n) {
			return fmt.Errorf("%w: %s is not an assigned number", ErrNotANumber, normalized)
		}
		return nil
	}
}
