package k8srequiredlabels

violation[{"msg": msg, "details": {"missing_labels": missing}}] {
          input.kind == "deployment"
          provided := { x | input.metadata.labels[x]}
          required := { "gatekeeper", "foo"}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("you must provide labels: %v", [missing])
        }
