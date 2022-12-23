/**
 * @name linux-6d4472d7bec39917b54e4e80245784ea5d60ce49-hiddev_open
 * @id cpp/linux/6d4472d7bec39917b54e4e80245784ea5d60ce49/hiddev_open
 * @description linux-6d4472d7bec39917b54e4e80245784ea5d60ce49-hiddev_open 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vlist_249, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("spin_lock_irq")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="list_lock"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="hiddev"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlist_249
		and (func.getEntryPoint().(BlockStmt).getStmt(26)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(26).getFollowingStmt()=target_0))
}

predicate func_1(Variable vlist_249, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("list_del")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="node"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlist_249
		and (func.getEntryPoint().(BlockStmt).getStmt(27)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(27).getFollowingStmt()=target_1))
}

predicate func_2(Variable vlist_249, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("spin_unlock_irq")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="list_lock"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="hiddev"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlist_249
		and (func.getEntryPoint().(BlockStmt).getStmt(28)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(28).getFollowingStmt()=target_2))
}

predicate func_3(Variable vlist_249) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="hiddev"
		and target_3.getQualifier().(VariableAccess).getTarget()=vlist_249)
}

from Function func, Variable vlist_249
where
not func_0(vlist_249, func)
and not func_1(vlist_249, func)
and not func_2(vlist_249, func)
and vlist_249.getType().hasName("hiddev_list *")
and func_3(vlist_249)
and vlist_249.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
