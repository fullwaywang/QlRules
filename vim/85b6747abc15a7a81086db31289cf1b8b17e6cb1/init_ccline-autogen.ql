/**
 * @name vim-85b6747abc15a7a81086db31289cf1b8b17e6cb1-init_ccline
 * @id cpp/vim/85b6747abc15a7a81086db31289cf1b8b17e6cb1/init-ccline
 * @description vim-85b6747abc15a7a81086db31289cf1b8b17e6cb1-src/ex_getln.c-init_ccline CVE-2022-0359
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vindent_1505, Literal target_0) {
		target_0.getValue()="1"
		and not target_0.getValue()="50"
		and target_0.getParent().(AddExpr).getParent().(ConditionalExpr).getElse().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vindent_1505
}

predicate func_1(Parameter vindent_1505, Variable vexmode_active, ConditionalExpr target_1) {
		target_1.getCondition().(VariableAccess).getTarget()=vexmode_active
		and target_1.getThen().(Literal).getValue()="250"
		and target_1.getElse().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vindent_1505
		and target_1.getElse().(AddExpr).getAnOperand() instanceof Literal
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("alloc_cmdbuff")
}

from Function func, Parameter vindent_1505, Variable vexmode_active, Literal target_0, ConditionalExpr target_1
where
func_0(vindent_1505, target_0)
and func_1(vindent_1505, vexmode_active, target_1)
and vindent_1505.getType().hasName("int")
and vexmode_active.getType().hasName("int")
and vindent_1505.getParentScope+() = func
and not vexmode_active.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
