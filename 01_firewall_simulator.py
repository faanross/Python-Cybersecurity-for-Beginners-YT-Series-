import random

def generate_random_ip():
    """Generate a random IP address."""
    return f"{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def check_firewall_rules(ip, rules):
    """Check if the IP address matches any firewall rule and return the action."""
    for rule_ip, action in rules.items():
        if ip == rule_ip:
            return action
    return "allow"  # Default action if no rule matches

def main():
    # Define the firewall rules (key: IP address, value: action)
    firewall_rules = {
        "192.168.1.10": "allow",
        "192.168.1.20": "block",
        "10.0.0.5": "allow",
        "10.0.0.6": "block"
    }

      # Simulate network traffic
    for _ in range(10):
        ip_address = generate_random_ip()
        action = check_firewall_rules(ip_address, firewall_rules)
        print(f"IP: {ip_address}, Action: {action}")