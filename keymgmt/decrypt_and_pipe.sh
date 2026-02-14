( gpg --batch --quiet --no-tty --decrypt inputs.txt.gpg | sed -n '1,4p'; cat ) \
| script -q -c 'env -i HOME="$HOME" PATH="/usr/bin:/bin" bash -c "set -o pipefail; stty -echo; trap \"stty echo\" EXIT; exec ../build/main"' /dev/null
