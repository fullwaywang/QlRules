/**
 * @name linux-21a87d88c2253350e115029f14fe2a10a7e6c856-nilfs_read_inode_common
 * @id cpp/linux/21a87d88c2253350e115029f14fe2a10a7e6c856/nilfs_read_inode_common
 * @description linux-21a87d88c2253350e115029f14fe2a10a7e6c856-nilfs_read_inode_common 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vinode_441, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("nilfs_is_metadata_file_inode")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_441
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="i_mode"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinode_441
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="61440"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="32768"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-5"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="5"
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vinode_441) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="i_mtime"
		and target_1.getQualifier().(VariableAccess).getTarget()=vinode_441)
}

from Function func, Parameter vinode_441
where
not func_0(vinode_441, func)
and vinode_441.getType().hasName("inode *")
and func_1(vinode_441)
and vinode_441.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
