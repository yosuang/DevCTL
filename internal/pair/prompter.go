package pair

import (
	"bufio"
	"crypto/subtle"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	"golang.org/x/term"
)

// Prompter reads the pairing URI and the transfer passphrase.
// The terminal implementation fails when stdin is not a terminal.
type Prompter interface {
	// URI reads one proxy URI.
	URI() (string, error)
	// Passphrase reads the transfer passphrase.
	// When confirm is true, it reads the passphrase twice and asks again when the two entries differ.
	Passphrase(confirm bool) (string, error)
}

type terminalPrompter struct{}

// TerminalPrompter reads prompts from the process terminal.
// It returns not_a_tty when stdin is not a terminal.
func TerminalPrompter() Prompter {
	return terminalPrompter{}
}

func (terminalPrompter) URI() (string, error) {
	if !stdinTerminal() {
		return "", localCode("not_a_tty", "stdin is not a terminal")
	}
	if _, err := io.WriteString(os.Stderr, "Hysteria2 URI: "); err != nil {
		return "", localCode("not_a_tty", "stdin is not a terminal")
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", localCode("uri_invalid", "uri is not usable")
	}
	raw := stripOneTrailingNewline([]byte(line))
	if err := validatePairURI(raw); err != nil {
		return "", err
	}
	return string(raw), nil
}

func (terminalPrompter) Passphrase(confirm bool) (string, error) {
	if !stdinTerminal() {
		return "", localCode("not_a_tty", "stdin is not a terminal")
	}
	for {
		first, err := readSecret("Transfer passphrase (not this computer's login password): ")
		if err != nil {
			return "", err
		}
		if utf8.RuneCount(first) < vocabulary.PassphraseMinCodepoints {
			zeroBytes(first)
			return "", localCode("passphrase_rejected", "passphrase is too short")
		}
		if !confirm {
			out := string(first)
			zeroBytes(first)
			return out, nil
		}
		second, err := readSecret("Transfer passphrase again: ")
		if err != nil {
			zeroBytes(first)
			return "", err
		}
		match := subtle.ConstantTimeCompare(first, second) == 1
		zeroBytes(second)
		if !match {
			zeroBytes(first)
			fmt.Fprintln(os.Stderr, "passphrase_rejected: entries did not match")
			continue
		}
		out := string(first)
		zeroBytes(first)
		return out, nil
	}
}

func stdinTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

func readSecret(prompt string) ([]byte, error) {
	if _, err := io.WriteString(os.Stderr, prompt); err != nil {
		return nil, localCode("passphrase_rejected", "passphrase could not be read")
	}
	buf, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		zeroBytes(buf)
		return nil, localCode("passphrase_rejected", "passphrase could not be read")
	}
	return buf, nil
}
