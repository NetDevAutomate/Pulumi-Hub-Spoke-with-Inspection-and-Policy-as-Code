import pulumi
from pulumi_policy import ResourceValidationArgs, ResourceValidationPolicy, PolicyPack, EnforcementLevel
import re

def firewall_rule_validator(args: ResourceValidationArgs, report_violation):
    # Check if the resource is an AWS Network Firewall rule group
    if args.resource_type == "aws:networkfirewall/ruleGroup:RuleGroup":
        rule_group = args.props.get("ruleGroup", {})
        
        # 1. Stateless Rule Validation
        stateless_rules = rule_group.get("rulesSource", {}).get("statelessRulesAndCustomActions", {}).get("statelessRules", [])
        for rule in stateless_rules:
            match_attributes = rule.get("ruleDefinition", {}).get("matchAttributes", {})
            actions = rule.get("ruleDefinition", {}).get("actions", [])
            sources = match_attributes.get("sources", [])
            destinations = match_attributes.get("destinations", [])
            destination_ports = match_attributes.get("destinationPorts", [])

            # Check if the destination port matches 80 and if the source/destination allows unrestricted access
            for dest in destinations:
                if dest.get("addressDefinition") in ("0.0.0.0/0", "any"):
                    for dest_port in destination_ports:
                        if dest_port.get("toPort") == 80 and "aws:pass" in actions:
                            report_violation(
                                "Stateless rule allows unrestricted access (0.0.0.0/0 or 'any') to TCP port 80 with action 'aws:pass'."
                            )

        # 2. Stateful Rule Validation
        stateful_rules = rule_group.get("rulesSource", {}).get("statefulRules", [])
        for rule in stateful_rules:
            header = rule.get("header", {})
            action = rule.get("action", "")

            # Check if the stateful rule has HTTP protocol and unrestricted destination
            if header.get("protocol") == "HTTP" and header.get("destination") in ("ANY", "0.0.0.0/0") and action.upper() == "PASS":
                report_violation(
                    "Stateful rule allows unrestricted access with 'PASS' action, protocol HTTP, and destination ANY."
                )

        # 3. Suricata Rule Validation
        suricata_rules = rule_group.get("rulesSource", {}).get("rulesString", "")
        if suricata_rules:
            # Split the rules into individual lines
            rules = suricata_rules.strip().split('\n')
            for rule in rules:
                rule = rule.strip()
                if rule.startswith('pass'):
                    # Extract header and options
                    header_and_options = rule.split('(')
                    header = header_and_options[0].strip()
                    # Ignore options for this check
                    header_parts = header.split()

                    if len(header_parts) >= 7:
                        action = header_parts[0]
                        protocol = header_parts[1]
                        src_ip = header_parts[2]
                        src_port = header_parts[3]
                        direction = header_parts[4]
                        dst_ip = header_parts[5]
                        dst_port = header_parts[6]

                        # Check if action is 'pass'
                        if action.lower() == 'pass':
                            # Check if protocol is 'tcp'
                            if protocol.lower() == 'tcp':
                                # Check if destination is '$EXTERNAL_NET', 'any', or '0.0.0.0/0'
                                if dst_ip in ('$EXTERNAL_NET', 'any', '0.0.0.0/0'):
                                    # Check if destination port is '80'
                                    if dst_port == '80':
                                        # Report violation
                                        report_violation(
                                            f"Suricata rule allows access with 'PASS' action, protocol TCP, destination {dst_ip}, and port 80."
                                        )
        
    # Also check security group rules for 0.0.0.0/0
    elif args.resource_type == "aws:ec2/securityGroupRule:SecurityGroupRule":
        cidr_blocks = args.props.get("cidrBlocks")
        to_port = args.props.get("toPort")

        if cidr_blocks and "0.0.0.0/0" in cidr_blocks and to_port == 80:
            report_violation(
                "Security group rule allows unrestricted access (0.0.0.0/0) to TCP port 80."
            )

# Define the policy
policy = ResourceValidationPolicy(
    name="no-unrestricted-access-with-pass-action-and-port-80",
    description="Ensure no firewall rule allows access with 'PASS' action, protocol TCP, destination $EXTERNAL_NET, 0.0.0.0/0, or 'any', and port 80.",
    validate=firewall_rule_validator,
    enforcement_level=EnforcementLevel.MANDATORY  # Set policy to MANDATORY to block deployments
)

# Create the policy pack
PolicyPack(
    name="aws-network-firewall-policy",
    policies=[policy],
)