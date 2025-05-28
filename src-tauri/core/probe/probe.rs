use regex::Regex;
use std::{collections::HashMap, path::Path, io::{BufRead, BufReader}, fs};

#[derive(Clone)]
pub struct Probe {
    pub payload: Vec<u8>,
    pub pattern: Regex,
}

pub fn load_probes_from_nmap<P: AsRef<Path>>(path: P) -> Result<HashMap<u16, Vec<Probe>>, Box<dyn std::error::Error>> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);

    let mut probes_map: HashMap<u16, Vec<Probe>> = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        if line.starts_with("match ") {
            if let Some(probe) = parse_probe_line(&line)? {
                for port in &probe.ports {
                    probes_map.entry(*port)
                        .or_insert_with(Vec::new)
                        .push(probe.probe.clone());
                }
            }
        }
    }

    Ok(probes_map)
}

struct ParsedProbe {
    probe: Probe,
    ports: Vec<u16>,
}

fn parse_probe_line(line: &str) -> Result<Option<ParsedProbe>, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        return Ok(None);
    }

    let service = parts[1];
    let regex_str = parts[2];
    let port_spec = parts.get(3);

    let re_pattern = extract_regex_pattern(regex_str)?;
    let regex = Regex::new(&re_pattern)?;

    let payload = format!("{}\r\n", service).into_bytes();

    let ports = match port_spec {
        Some(spec) => parse_port_spec(spec)?,
        None => vec![],
    };

    if ports.is_empty() {
        return Ok(None);
    }

    let probe = Probe {
        payload,
        pattern: regex,
    };

    Ok(Some(ParsedProbe {
        probe,
        ports,
    }))
}

fn extract_regex_pattern(s: &str) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(start) = s.find('|') {
        let start = start + 1;
        if let Some(end) = s[start..].find('|') {
            return Ok(s[start..start + end].to_string());
        }
    }
    Err("Invalid regex pattern in probe line".into())
}

fn parse_port_spec(s: &str) -> Result<Vec<u16>, Box<dyn std::error::Error>> {
    if s.starts_with("p/") {
        let port_str = s.trim_start_matches("p/");
        if let Ok(port) = port_str.parse::<u16>() {
            return Ok(vec![port]);
        }
    } else if s == "sV" {
        return Ok(vec![
            80, 443, 21, 22, 25, 53, 110, 143, 993, 995, 3306, 3389, 5900, 8080,
        ]);
    }
    Ok(vec![])
}