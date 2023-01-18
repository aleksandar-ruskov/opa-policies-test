package kubernetes.admission
import data.kubernetes.namespaces

# POLICY FOR ONLY ALLLOWING THE CREATION/UPDATING OF NAMESPACES IF THEY MATCH A SPECIFIC NAME FORMAT (NAMING CONVENTION)

# The operations which will be taken into account for this policy.
operations := {"CREATE", "UPDATE"}

# The type of resource to which the policy is applied.
resources := {"Namespace", "namespace"}

deny[msg] {
    # Only continue if the resouce getting created/updated is in the specified list (a namespace)
    resources[input.request.kind.kind]
    # Only apply the policy if the operation is create/update
	operations[input.request.operation]

    # Store the namespace name in a variable
	ns_name := input.request.object.metadata.name

    # Check if the specified namespace name matches any of the allowed formats. If it does not, then continue as the policy is violated.
	not fqdn_matches_any(ns_name, valid_ns_name_format)

    # Produce the message which will be displayed if the namespace does not comply with the policy.
	msg := sprintf("invalid name used for the namespace: %q! The correct format should be: lbg-bcb-project-<project number> or lbg-cloudfirst-project-<project number>", [ns_name])
}

# Define the allowed namespace name formats (naming convention)
valid_ns_name_format := {ns_name |
    # Define the allowed name formats! The * WILL BE EXPECTED TO BE A NUMBER.
	allowlist := "lbg-bcb-project-*,lbg-cloudfirst-project-*"  
	ns_names := split(allowlist, ",")
    # ns_name is set with all names in the ns_names array in a sequestial manner.
	ns_name := ns_names[_]
}

fqdn_matches_any(str, patterns) {
    # Sequentally we would try to match str to all the patterns in the array. (This is what the [_] denotes)
	fqdn_matches(str, patterns[_])
}

# Function which mathces a string to a pattern (name format/convention).
fqdn_matches(str, pattern) {
    # Split the pattern into parts
	pattern_parts := split(pattern, "-")
    n_pattern_parts := count(pattern_parts)
    final_index := n_pattern_parts - 1

    # Check that the final index is a wildcard
	pattern_parts[final_index] == "*"

    # Extract the pattern prefix (remove the wildcard)
	pattern_prefix := trim(pattern, "*")
    
    # Check that the suggested namespace name starts with the required prefix (follows the correct format)
	startswith(str, pattern_prefix)

    # Get the suffix part of the namespace name (the wildcard part)
    ns_name_suffix := trim(str, pattern_prefix)

    # We need to check that the wildcard part is a number. If it is not a number then the policy is violated.
    to_number(ns_name_suffix) 
}

# If the required format does not contain wildcard, then the name of the namespace must be the same as the required pattern.
fqdn_matches(str, pattern) {
    not contains(pattern, "*")
    str == pattern
}