A simple program that uses the HaveIBeenPwned password api to check if a passed password or list of passwords has been compromised in data breaches. <br>
Compiles to a binary which runs as a cli tool. Alternatively callable directly from lib or with included python bindings. 

CLI options: <br>
Options: <br>
  -p, --password <PASSWORD>  Check a single password<br>
  -l, --list <FILE>          Check passwords from a file (one per line)<br>
  -s, --show                 Display the actual password in the output comparison. Defaults to false if flag not passed.<br>
  -a, --anonymous            Accept a sha1 hash rather than a raw text password. Defaults to false.<br>
  -h, --help                 Print help<br>
  -V, --version              Print version<br>
