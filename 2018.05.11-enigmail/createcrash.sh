#!/bin/bash

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <message> <keyid>"
  exit 1
fi

gen_boundary() {
  echo -n "=========="
  cat /dev/urandom | LC_ALL=C tr -dc '0-9' | fold -w 10 | head -n 1
}

encrypt() {
  local boundary=$(gen_boundary)
  local pgpmsg=$(echo "$1" | gpg -ear $2)
  echo -n "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\";
 boundary=\"$boundary\"

--$boundary
Content-Type: application/pgp-encrypted
Content-Description: PGP/MIME version identification

Version: 1

--$boundary
Content-Type: application/octet-stream; name="encrypted.asc"
Content-Description: OpenPGP encrypted message
Content-Disposition: inline; filename="encrypted.asc"

$pgpmsg

--$boundary--
"
}

first=$(encrypt "$1" "$2")
encrypt "$first" "$2"
