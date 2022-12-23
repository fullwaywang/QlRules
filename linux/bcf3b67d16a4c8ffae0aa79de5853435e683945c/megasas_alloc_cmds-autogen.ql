/**
 * @name linux-bcf3b67d16a4c8ffae0aa79de5853435e683945c-megasas_alloc_cmds
 * @id cpp/linux/bcf3b67d16a4c8ffae0aa79de5853435e683945c/megasas_alloc_cmds
 * @description linux-bcf3b67d16a4c8ffae0aa79de5853435e683945c-megasas_alloc_cmds 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vinstance_4136) {
	exists(ReturnStmt target_0 |
		target_0.getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_0.getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="12"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("megasas_create_frame_pool")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinstance_4136)
}

from Function func, Parameter vinstance_4136
where
not func_0(vinstance_4136)
and vinstance_4136.getType().hasName("megasas_instance *")
and vinstance_4136.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
