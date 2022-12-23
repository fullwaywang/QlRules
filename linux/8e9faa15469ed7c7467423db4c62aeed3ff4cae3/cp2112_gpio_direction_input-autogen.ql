/**
 * @name linux-8e9faa15469ed7c7467423db4c62aeed3ff4cae3-cp2112_gpio_direction_input
 * @id cpp/linux/8e9faa15469ed7c7467423db4c62aeed3ff4cae3/cp2112-gpio-direction-input
 * @description linux-8e9faa15469ed7c7467423db4c62aeed3ff4cae3-cp2112_gpio_direction_input 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="0"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vret_189) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vret_189
		and target_3.getGreaterOperand() instanceof Literal)
}

from Function func, Variable vret_189
where
func_2(func)
and func_3(vret_189)
and vret_189.getType().hasName("int")
and vret_189.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
