package k8srequiredlabels

deny[msg] {
          input.kind == "deployment"
          provided := {label | input.metadata.labels[label]}
          required := { "gatekeeper", "foo"}
          missing := required - provided
          count(missing) == 0
          msg := sprintf("you must provide labels: %v", [missing])
        }
