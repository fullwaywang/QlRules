/**
 * @name linux-5e3cc1ee1405a7eb3487ed24f786dec01b4cbe1f-v9fs_stat2inode
 * @id cpp/linux/5e3cc1ee1405a7eb3487ed24f786dec01b4cbe1f/v9fs_stat2inode
 * @description linux-5e3cc1ee1405a7eb3487ed24f786dec01b4cbe1f-v9fs_stat2inode 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_1177, Parameter vstat_1177) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("i_size_write")
		and not target_0.getTarget().hasName("v9fs_i_size_write")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vinode_1177
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="length"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstat_1177)
}

predicate func_1(Parameter vinode_1177, Parameter vstat_1177, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getType().hasName("unsigned int")
		and target_1.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand() instanceof Literal
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("v9fs_i_size_write")
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_1177
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="length"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstat_1177
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vinode_1177, Parameter vstat_1177) {
	exists(BinaryBitwiseOperation target_2 |
		target_2.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_2.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstat_1177
		and target_2.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_2.getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getRightOperand() instanceof Literal
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="i_blocks"
		and target_2.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_1177)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="512"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="1"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="9"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Parameter vinode_1177) {
	exists(BinaryBitwiseOperation target_6 |
		target_6.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("i_size_read")
		and target_6.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_1177
		and target_6.getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_6.getLeftOperand().(SubExpr).getRightOperand() instanceof Literal
		and target_6.getRightOperand() instanceof Literal
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="i_blocks"
		and target_6.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_1177)
}

predicate func_7(Parameter vstat_1177) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="length"
		and target_7.getQualifier().(VariableAccess).getTarget()=vstat_1177)
}

from Function func, Parameter vinode_1177, Parameter vstat_1177
where
func_0(vinode_1177, vstat_1177)
and not func_1(vinode_1177, vstat_1177, func)
and not func_2(vinode_1177, vstat_1177)
and func_3(func)
and func_4(func)
and func_5(func)
and func_6(vinode_1177)
and vinode_1177.getType().hasName("inode *")
and vstat_1177.getType().hasName("p9_wstat *")
and func_7(vstat_1177)
and vinode_1177.getParentScope+() = func
and vstat_1177.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
