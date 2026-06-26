package main

# Deny containers without CPU/memory limits defined
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.resources.limits.cpu
    msg := sprintf(
        "Container '%v' is missing resources.limits.cpu",
        [container.name]
    )
}

deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf(
        "Container '%v' is missing resources.limits.memory",
        [container.name]
    )
}
