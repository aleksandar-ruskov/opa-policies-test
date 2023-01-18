package kubernetes.admission
import data.kubernetes.namespaces

# get_message(parameters, _default) = msg {
#     not parameters.message
#     msg := _default
# }
# get_message(parameters, _default) = msg {
#     msg := parameters.message
# }

resources := {"Ingress", "ingress"}
operations := {"CREATE", "UPDATE"}

deny[msg] {
    # Only continue if the resouce getting created/updated is in the specified list (a namespace)
    resources[input.request.kind.kind]
    # Only apply the policy if the operation is create/update
	operations[input.request.operation]

    provided := {label | input.request.object.metadata.labels[label]}

    required_labels := {label |
        label_list := namespaces[input.request.namespace].metadata.annotations["required-labels"]
        labels := split(label_list, ",")
        label := labels[_]
    }

    missing := required_labels - provided
    count(missing) > 0
    msg := sprintf("you must provide labels: %v", [missing])
}



# violation[{"msg": msg}] {
#     value := input.review.object.metadata.labels[key]
#     expected := input.parameters.labels[_]
#     expected.key == key
#     # do not match if allowedRegex is not defined, or is an empty string
#     expected.allowedRegex != ""
#     not re_match(expected.allowedRegex, value)
#     def_msg := sprintf("Label <%v: %v> does not satisfy allowed regex: %v", [key, value, expected.allowedRegex])
#     msg := get_message(input.parameters, def_msg)
# }