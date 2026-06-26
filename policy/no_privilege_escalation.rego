package main

# Deny containers that allow privilege escalation
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf(
        "Container '%v' must set securityContext.allowPrivilegeEscalation: false",
        [container.name]
    )
}

# Also catch the case where securityContext is missing entirely
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext
    msg := sprintf(
        "Container '%v' is missing securityContext entirely — allowPrivilegeEscalation must be explicitly false",
        [container.name]
    )
}
