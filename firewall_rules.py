import pulumi_aws as aws
import pulumi as pulumi


def create_firewall_policy(supernet_cidr: str) -> pulumi.Output[str]:
    # Stateless rule that drops remote SSH traffic (TCP/22)
    drop_remote = aws.networkfirewall.RuleGroup(
        "drop-remote",
        aws.networkfirewall.RuleGroupArgs(
            capacity=2,
            name="drop-remote",
            type="STATELESS",
            rule_group={
                "rules_source": {
                    "stateless_rules_and_custom_actions": {
                        "stateless_rules": [{
                            "priority": 1,
                            "rule_definition": {
                                "actions": ["aws:drop"],
                                "match_attributes": {
                                    "protocols": [6],
                                    "sources": [{
                                        "address_definition": "0.0.0.0/0"
                                    }],
                                    "source_ports": [{
                                        "from_port": 22,
                                        "to_port": 22,
                                    }],
                                    "destinations": [{
                                        "address_definition": "0.0.0.0/0"
                                    }],
                                    "destination_ports": [{
                                        "from_port": 22,
                                        "to_port": 22,
                                    }]
                                }
                            }
                        }]
                    }
                }
            }
        )
    )

    # Stateless rule that allows unrestricted HTTP traffic (TCP/80)
    allow_unrestricted_http = aws.networkfirewall.RuleGroup(
        "allow-unrestricted-http",
        aws.networkfirewall.RuleGroupArgs(
            capacity=2,
            name="allow-unrestricted-http",
            type="STATELESS",
            rule_group={
                "rules_source": {
                    "stateless_rules_and_custom_actions": {
                        "stateless_rules": [{
                            "priority": 2,
                            "rule_definition": {
                                "actions": ["aws:pass"],
                                "match_attributes": {
                                    "protocols": [6],  # TCP
                                    "sources": [{
                                        "address_definition": "0.0.0.0/0"
                                    }],
                                    "source_ports": [{
                                        "from_port": 80,
                                        "to_port": 80,
                                    }],
                                    "destinations": [{
                                        "address_definition": "0.0.0.0/0"
                                    }],
                                    "destination_ports": [{
                                        "from_port": 80,
                                        "to_port": 80,
                                    }]
                                }
                            }
                        }]
                    }
                }
            }
        )
    )

    # Stateful rule that allows ICMP traffic within the SUPERNET
    allow_icmp = aws.networkfirewall.RuleGroup(
        "allow-icmp",
        aws.networkfirewall.RuleGroupArgs(
            capacity=100,
            type="STATEFUL",
            rule_group={
                "rule_variables": {
                    "ip_sets": [{
                        "key": "SUPERNET",
                        "ip_set": {
                            "definition": [supernet_cidr]
                        }
                    }]
                },
                "rules_source": {
                    "rules_string": 'pass icmp $SUPERNET any -> $SUPERNET any (msg: "Allowing ICMP packets"; sid:2; rev:1;)'
                },
                "stateful_rule_options": {
                    "rule_order": "STRICT_ORDER"
                },
            }
        )
    )

    # Stateful rule that allows unrestricted HTTP traffic
    allow_unrestricted_http_stateful = aws.networkfirewall.RuleGroup(
        "allow-unrestricted-http-stateful",
        aws.networkfirewall.RuleGroupArgs(
            capacity=50,
            name="allow-unrestricted-http-stateful",
            type="STATEFUL",
            rule_group={
                "rules_source": {
                    "stateful_rules": [{
                        "action": "PASS",
                        "header": {
                            "protocol": "HTTP",
                            "direction": "ANY",
                            "source": "0.0.0.0/0",
                            "source_port": "80",
                            "destination": "ANY",  # Unrestricted destination
                            "destination_port": "80",  # Port 80
                        },
                        "rule_options": [{
                            "keyword": "sid",
                            "settings": ["1"],
                        }],
                    }]
                }
            }
        )
    )

    # Stateful rule that allows Amazon HTTPS traffic using Suricata format
    allow_amazon = aws.networkfirewall.RuleGroup(
        "allow-amazon",
        aws.networkfirewall.RuleGroupArgs(
            capacity=100,
            name="allow-amazon",
            type="STATEFUL",
            rule_group=aws.networkfirewall.RuleGroupRuleGroupArgs(
                rules_source=aws.networkfirewall.RuleGroupRuleGroupRulesSourceArgs(
                    rules_string='pass tcp any any <> $EXTERNAL_NET 443 (msg:"Allowing TCP in port 443"; flow:not_established; sid:892123; rev:1;)\n' +
                    'pass tls any any -> $EXTERNAL_NET 443 (tls.sni; dotprefix; content:".amazon.com"; endswith; msg:"Allowing .amazon.com HTTPS requests"; sid:892125; rev:1;)'
                ),
                stateful_rule_options={
                    "rule_order": "STRICT_ORDER",
                },
            )
        )
    )

    # Suricata rule to allow unrestricted HTTP traffic
    allow_unrestricted_http_suricata = aws.networkfirewall.RuleGroup(
        "allow-unrestricted-http-suricata",
        aws.networkfirewall.RuleGroupArgs(
            capacity=100,
            name="allow-unrestricted-http-suricata",
            type="STATEFUL",
            rule_group=aws.networkfirewall.RuleGroupRuleGroupArgs(
                rules_source=aws.networkfirewall.RuleGroupRuleGroupRulesSourceArgs(
                    rules_string='pass tcp any any -> any 80 (msg:"Allowing HTTP traffic to any destination on port 80"; sid:100001; rev:1;)'
                ),
                stateful_rule_options={
                    "rule_order": "STRICT_ORDER",
                },
            )
        )
    )

    # Firewall policy with all the rules in order
    policy = aws.networkfirewall.FirewallPolicy(
        "firewall-policy",
        aws.networkfirewall.FirewallPolicyArgs(
            firewall_policy=aws.networkfirewall.FirewallPolicyFirewallPolicyArgs(
                stateless_default_actions=["aws:forward_to_sfe"],
                stateless_fragment_default_actions=["aws:forward_to_sfe"],
                stateful_default_actions=[
                    "aws:drop_strict", "aws:alert_strict"],
                stateful_engine_options={
                    "rule_order": "STRICT_ORDER"
                },
                stateless_rule_group_references=[
                    {
                        "priority": 10,
                        "resource_arn": drop_remote.arn
                    },
                    {
                        "priority": 20,
                        "resource_arn": allow_unrestricted_http.arn  # After drop-remote
                    }
                ],
                stateful_rule_group_references=[
                    {
                        "priority": 10,
                        "resource_arn": allow_icmp.arn
                    },
                    {
                        "priority": 20,
                        "resource_arn": allow_unrestricted_http_stateful.arn  # After allow-icmp
                    },
                    {
                        "priority": 30,
                        "resource_arn": allow_amazon.arn
                    },
                    {
                        "priority": 40,
                        "resource_arn": allow_unrestricted_http_suricata.arn  # After allow-amazon
                    }
                ]
            )
        )
    )

    return policy.arn