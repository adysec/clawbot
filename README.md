# clawbot

iLink bot management tool with CLI and web dashboard.

## Usage

```
Usage: clawbot-web <COMMAND>

Commands:
  login              Log in with a QR code and save the account locally
  qrcode             Request a login QR code and print it as JSON
  qrcode-status      Query a login QR code status
  account            Inspect saved accounts
  get-context-token  Wait for the next inbound message and print its context token
  send               Send a text, image, or file message
  serve              Start the web dashboard server
  help               Print this message or the help of the given subcommand(s)
```

### Commands

```bash
cargo run -- serve
```
