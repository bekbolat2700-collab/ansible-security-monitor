package main

# Deny container images using the ":latest" tag (or no tag at all)
deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    image := container.image
    endswith(image, ":latest")
    msg := sprintf(
        "Container '%v' uses ':latest' tag in image '%v' — pin to a specific version",
        [container.name, image]
    )
}

deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    image := container.image
    not contains(image, ":")
    msg := sprintf(
        "Container '%v' image '%v' has no tag — pin to a specific version",
        [container.name, image]
    )
}
