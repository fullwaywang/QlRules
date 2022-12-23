/**
 * @name linux-8019ad13ef7f64be44d4f892af9c840179009254-inode_init_always
 * @id cpp/linux/8019ad13ef7f64be44d4f892af9c840179009254/inode-init-always
 * @description linux-8019ad13ef7f64be44d4f892af9c840179009254-inode_init_always 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_132, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("atomic64_set")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="i_sequence"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_132
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vinode_132) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="i_flags"
		and target_1.getQualifier().(VariableAccess).getTarget()=vinode_132)
}

from Function func, Parameter vinode_132
where
not func_0(vinode_132, func)
and vinode_132.getType().hasName("inode *")
and func_1(vinode_132)
and vinode_132.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
