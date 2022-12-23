/**
 * @name linux-28d76df18f0ad5bcf5fa48510b225f0ed262a99b-compat_mpt_command
 * @id cpp/linux/28d76df18f0ad5bcf5fa48510b225f0ed262a99b/compat_mpt_command
 * @description linux-28d76df18f0ad5bcf5fa48510b225f0ed262a99b-compat_mpt_command 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable viocnumX_2872) {
	exists(Literal target_0 |
		target_0.getValue()="2884"
		and not target_0.getValue()="2771"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="7mptctl::compat_mpt_command @%d - ioc%d not found!\n"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=viocnumX_2872)
}

from Function func, Variable viocnumX_2872
where
func_0(viocnumX_2872)
and viocnumX_2872.getType().hasName("int")
and viocnumX_2872.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
