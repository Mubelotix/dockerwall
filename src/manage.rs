use std::error::Error;
use crate::control::send_control_command;

pub fn send_create(name: &str, subnet: Option<&str>, allowed_domains: &[String]) -> Result<(), Box<dyn Error + Send + Sync>> {
    let subnet = subnet.unwrap_or("");
    let payload = format!("CREATE\t{name}\t{subnet}\t{}\n", allowed_domains.join(","));
    send_control_command(&payload)?;
    println!("requested creation of ipset '{name}'");
    Ok(())
}

pub fn send_remove(name: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let payload = format!("REMOVE\t{name}\n");
    send_control_command(&payload)?;
    println!("requested removal of ipset '{name}'");
    Ok(())
}
