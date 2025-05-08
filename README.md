A simple program that uses the HaveIBeenPwned password api to check if a passed password or list of passwords has been compromised in data breaches. 

Compiles to a binary which runs as a cli tool. Alternatively callable directly from lib or with included python bindings. 

CLI options: 
Options:
  -p, --password <PASSWORD>  Check a single password
  -l, --list <FILE>          Check passwords from a file (one per line)
  -s, --show                 Display the actual password in the output comparison. Defaults to false if flag not passed.
  -a, --anonymous            Accept a sha1 hash rather than a raw text password. Defaults to false.
  -h, --help                 Print help
  -V, --version              Print version
