ctxt = open("morse").read()

morse = ctxt.replace("-", "").replace("dah", "-").replace("dit", ".").replace("di", ".")
print morse
