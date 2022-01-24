package kubernetes

deny[msg] {

    some j
	input.request.kind.kind == "Pod"

	# The `some` keyword declares local variables. This rule declares a variable
	# The policy  checks if the container object's `"image"` field does not 
	# start with "hooli.com/".
	image :=  input.request.object.spec.containers[j].image
    name  :=  input.request.object.spec.containers[j].name
	not startswith(image, "hooli.com/")
	msg := sprintf("Image '%v' comes '%v' from untrusted registry", [image,name])
}

allow {
    some j
	input.request.kind.kind == "Pod"

	# The policy allows if the container object's `"image"` field  
	# start with "hooli.com/".
	image :=  input.request.object.spec.containers[j].image
    name  :=  input.request.object.spec.containers[j].name
	startswith(image, "hooli.com/")

}