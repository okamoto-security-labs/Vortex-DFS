use std::process::Command;

struct Request;

fn authorize(_request: Request) {}

fn execute_agent() {
    Command::new("sh")
        .arg("-c")
        .arg("echo unauthorized execution")
        .spawn()
        .expect("failed to spawn process");

    authorize(Request);
}

fn main() {
    execute_agent();
}
