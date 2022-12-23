/**
 * @name linux-b98e762e3d71e893b221f871825dc64694cfb258-nbd_add_socket
 * @id cpp/linux/b98e762e3d71e893b221f871825dc64694cfb258/nbd_add_socket
 * @description linux-b98e762e3d71e893b221f871825dc64694cfb258-nbd_add_socket 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vnbd_1012, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("blk_mq_freeze_queue")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="queue"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="disk"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnbd_1012
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vnbd_1012, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("blk_mq_unfreeze_queue")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="queue"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="disk"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnbd_1012
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_1))
}

predicate func_3(Parameter vnbd_1012, Parameter varg_1012, Variable verr_1019) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("nbd_get_socket")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vnbd_1012
		and target_3.getArgument(1).(VariableAccess).getTarget()=varg_1012
		and target_3.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=verr_1019)
}

predicate func_4(Parameter vnbd_1012) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="disk"
		and target_4.getQualifier().(VariableAccess).getTarget()=vnbd_1012)
}

from Function func, Parameter vnbd_1012, Parameter varg_1012, Variable verr_1019
where
not func_0(vnbd_1012, func)
and not func_1(vnbd_1012, func)
and vnbd_1012.getType().hasName("nbd_device *")
and func_3(vnbd_1012, varg_1012, verr_1019)
and func_4(vnbd_1012)
and varg_1012.getType().hasName("unsigned long")
and verr_1019.getType().hasName("int")
and vnbd_1012.getParentScope+() = func
and varg_1012.getParentScope+() = func
and verr_1019.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
