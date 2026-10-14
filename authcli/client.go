package authcli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// CmdClient writes a client library for the app's HTTP API; CmdClientTS is
// its one language so far, TypeScript (authhttp.TypeScriptClient). It reads
// the app's own operation list, so the app's custom plugins and their error
// codes are typed exactly, and touches no database.
//
//ds:def id=cmdclient-5tq8nw2k owner=@khanakia stability=stable
const (
	CmdClient   = "client"
	CmdClientTS = "ts"
)

// clientDirPerm is the mode of an output directory `auth client ts` creates,
// and clientFilePerm of the files it writes: source files, readable by all.
const (
	clientDirPerm  = 0o755
	clientFilePerm = 0o644
)

// client runs `auth client ts --out <dir>`: it writes the four TypeScript
// files into dir, creating it, and lists them on stdout.
func client(a *auth.Auth, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != CmdClientTS {
		fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	fs := newFlags(CmdClient, stderr)
	out := fs.String("out", "", "the directory to write the client's files into (created when missing)")
	if code, stop := parse(fs, args[1:]); stop {
		return code
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected argument %q\n%s", fs.Arg(0), usage)
		return ExitUsage
	}
	if *out == "" {
		fmt.Fprintf(stderr, "auth client ts: --out is required\n%s", usage)
		return ExitUsage
	}
	files, err := authhttp.TypeScriptClient(a)
	if err == nil {
		err = writeClient(*out, files, stdout)
	}
	if err != nil {
		fmt.Fprintln(stderr, "auth client ts:", err)
		return ExitFailed
	}
	return ExitOK
}

// writeClient writes files into dir in name order and prints each path.
func writeClient(dir string, files map[string][]byte, stdout io.Writer) error {
	if err := os.MkdirAll(dir, clientDirPerm); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		path := filepath.Join(dir, n)
		if err := os.WriteFile(path, files[n], clientFilePerm); err != nil {
			return err
		}
		fmt.Fprintln(stdout, path)
	}
	return nil
}
