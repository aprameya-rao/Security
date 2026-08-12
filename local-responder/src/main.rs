use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::config::ClientConfig;
use rdkafka::Message;
use serde::Deserialize;
use std::env;
use std::fs;
use std::process::Command;

fn load_dotenv() {
    let path = env::var("ENV_FILE").unwrap_or_else(|_| ".env".to_string());
    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("No {path} found; using env overrides/defaults.");
            return;
        }
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(idx) = line.find('=') {
            let key = line[..idx].trim();
            let value = line[idx + 1..].trim().trim_matches(|c| c == '"' || c == '\'');
            if env::var_os(key).is_none() {
                env::set_var(key, value);
            }
        }
    }
}


#[derive(Deserialize, Debug)]
struct SecurityEvent {
    pid: u32,
    command: String,
    is_known_threat: bool,
}

#[tokio::main]
async fn main() {
    println!("🛡️  Local Responder (Rust) is starting...");
    load_dotenv();
    let broker = env::var("KAFKA_BROKER").unwrap_or_else(|_| "192.168.1.16:9092".to_string());
    let consumer: StreamConsumer = ClientConfig::new()
        .set("group.id", "rust-responder-group")
        .set("bootstrap.servers", &broker) 
        .set("auto.offset.reset", "latest") // Only care about new attacks, ignore the past
        .create()
        .expect("Consumer creation failed");

    // 3. Subscribe to the execution topic
    consumer.subscribe(&["kill_commands"]).expect("Can't subscribe to specified topic");

    println!("📡 Listening for assassination orders on topic: 'kill_commands'...");

    // 4. The Infinite Event Loop
    loop {
        match consumer.recv().await {
            Err(e) => eprintln!("Kafka error: {}", e),
            Ok(m) => {
                let payload = match m.payload_view::<str>() {
                    None => "",
                    Some(Ok(s)) => s,
                    Some(Err(e)) => {
                        eprintln!("Error reading payload: {:?}", e);
                        ""
                    }
                };

                // 5. Parse the JSON and act!
                if let Ok(event) = serde_json::from_str::<SecurityEvent>(payload) {
                    if event.is_known_threat {
                        println!("🚨 THREAT DETECTED! Terminating PID: {} ({})", event.pid, event.command);
                        execute_kill(event.pid);
                    }
                }
            }
        }
    }
}

fn execute_kill(pid: u32) {
    let output = Command::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .output()
        .expect("Failed to execute kill command");

    if output.status.success() {
        println!("☠️  SUCCESS: Process {} was instantly eliminated.", pid);
    } else {
        eprintln!("⚠️  FAILED to kill {}. It might already be dead, or we lack root privileges.", pid);
    }
}
