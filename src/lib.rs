use sha1::Sha1;
use reqwest::blocking::get;
use std::process::exit;
use hex;
use num_format::{Locale, ToFormattedString};
use pyo3::{exceptions::PyValueError, prelude::*, wrap_pyfunction, types::PyModule};
use std::io::{self, Write};
use rpassword::prompt_password;

///Checks a single passed password against HIBP.
/// 
/// # Arguments 
/// # `password` - the password to be checked, passed in plaintext by default
/// # `show_pass` - false by default. If true, the text of the password will be shown in the function's output. 
/// # `hash_passed` - false by default. True if password is already sha1 hash. 
/// # `print_to_console` - tells function whether to print results. Primarily used to disable printing for python bindings.
/// 
/// # Returns
/// 
/// The number of times `password` was found in known data breaches. 
pub fn check_password(password: &str, show_pass: bool, hash_passed: bool, print_to_console: bool) -> Result<Option<i32>, &'static str>{
    let p_show: &str;
    if show_pass{
        p_show = password;
    }
    else{
        p_show = "Password";
    }
    let hash_hex: String;
    if hash_passed{
        hash_hex = password.to_string();
    }
    else{
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash = hasher.digest().bytes();
        hash_hex = hex::encode_upper(hash);
    }
    let prefix = &hash_hex[..5];
    let suffix = &hash_hex[5..];

    let url = format!("http://api.pwnedpasswords.com/range/{}", prefix);
    let response = get(&url).expect("Failed to fetch from HIBP API");

    if !response.status().is_success(){
        eprintln!("Error: Got HTTP {}", response.status());
        exit(1);
    }
    let body = response.text().expect("Failed to read response");
    for line in body.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() != 2 {
            continue;
        }
        let (resp_suffix, count) = (
            parts[0].trim(), 
            parts[1].trim()
            .parse::<i32>()
            .unwrap()
            .to_formatted_string(&Locale::en));
        if resp_suffix.eq_ignore_ascii_case(suffix) {
            if print_to_console{
                println!("{} was found in data breaches {} times.", p_show, count);
            }
            return Ok(Some(parts[1].trim().parse::<i32>().unwrap()));
        }
    }
    if print_to_console{
        println!("{} was NOT found in any known breaches.", p_show); 
    }
    Ok(Some(0))
}

pub fn pause_before_exit() {
    print!("\nPress Enter to exit...");
    io::stdout().flush().unwrap();
    let _ = io::stdin().read_line(&mut String::new());
}

pub fn check_next(){
    loop {
    let password = prompt_password("Enter a password to check or type `done`: ").expect("Failed to read password.");
    let password = password.trim();
    
    if password.eq_ignore_ascii_case("done"){
        break;
    }
    _ = check_password(&password, false, false, true);
    }
}

#[pyfunction]
fn py_check_password(password: &str, show_pass: bool, hash_passed: bool) -> PyResult<Option<i32>> {
    check_password(password, show_pass, hash_passed, false)
        .map_err(PyValueError::new_err)
}

#[pymodule]
fn hibp_check(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_check_password, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests{

    use super::*;

    #[test]
    fn test_check_pass(){
        let tp1 = "password";

        let hashed = false;
        let show = true;

        let count: i32 = match check_password(tp1, show, hashed, false){
            Ok(Some(value)) => value,
            Ok(None) => {
                panic!("Password check returned None");
            }
            Err(e) => {
                panic!("Password check failed: {}", e);
            }
        };
        assert!(count >= 21_303_723);
    }
    #[test]
    fn test_rare_pass(){
        //if this test fails first check that `neverbeenpwned` has not since been listed in an hibp leak
        let tp3 = "neverbeenpwned";

        let hashed = false;
        let show = true;
        
        let count: i32 = match check_password(tp3, show, hashed, false){
            Ok(Some(value)) => value,
            Ok(None) => {
                panic!("Password check returned None");
            }
            Err(e) => {
                panic!("Password check failed: {}", e);
            }
        };
        assert!(count == 0);
    }

    #[test]
    fn test_hashed_pass(){
        let tp = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8";
        let hashed = true;
        let show = true;

        let count: i32 = match check_password(tp, show, hashed, false){
            Ok(Some(value)) => value,
            Ok(None) => {
                panic!("Password check returned None");
            }
            Err(e) => {
                panic!("Password check failed: {}", e);
            }
        };
        assert!(count >= 21_303_723);
    }
}
