/**
 * @name linux-1fb254aa983bf190cfd685d40c64a480a9bafaee-xfs_setattr_nonsize
 * @id cpp/linux/1fb254aa983bf190cfd685d40c64a480a9bafaee/xfs-setattr-nonsize
 * @description linux-1fb254aa983bf190cfd685d40c64a480a9bafaee-xfs_setattr_nonsize 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vip_618, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("xfs_iunlock")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vip_618
		and target_0.getExpr().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getValue()="4"
		and target_0.getExpr().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getExpr().(FunctionCall).getArgument(1).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
		and (func.getEntryPoint().(BlockStmt).getStmt(33)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(33).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vip_618) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("xfs_iunlock")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vip_618
		and target_1.getArgument(1).(BinaryBitwiseOperation).getValue()="4"
		and target_1.getArgument(1).(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getArgument(1).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2")
}

from Function func, Parameter vip_618
where
not func_0(vip_618, func)
and vip_618.getType().hasName("xfs_inode *")
and func_1(vip_618)
and vip_618.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
