def calculate(expression: str):
    return eval(expression)


def compile_formula(formula: str, variables: str):
    exec(f"{formula} = {variables}")
    return "ok"
