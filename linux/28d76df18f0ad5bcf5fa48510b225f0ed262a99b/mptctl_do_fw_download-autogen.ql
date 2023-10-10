/**
 * @name linux-28d76df18f0ad5bcf5fa48510b225f0ed262a99b-mptctl_do_fw_download
 * @id cpp/linux/28d76df18f0ad5bcf5fa48510b225f0ed262a99b/mptctl_do_fw_download
 * @description linux-28d76df18f0ad5bcf5fa48510b225f0ed262a99b-mptctl_do_fw_download 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vn_801, Parameter vufwbuf_787, Variable viocp_791) {
	exists(Literal target_0 |
		target_0.getValue()="928"
		and not target_0.getValue()="911"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3mptctl: %s: ERROR - %s@%d::_ioctl_fwdl - Unable to copy f/w buffer hunk#%d @ %p\n"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viocp_791
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="drivers/message/fusion/mptctl.c"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vn_801
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vufwbuf_787)
}

predicate func_1(Variable vmptctl_id, Variable vmf_790, Variable viocp_791) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmf_790
		and target_1.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mpt_get_msg_frame")
		and target_1.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmptctl_id
		and target_1.getCondition().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=viocp_791
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-11"
		and target_1.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="11"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof RelationalOperation)
}

predicate func_2(Variable viocp_791) {
	exists(BitwiseAndExpr target_2 |
		target_2.getLeftOperand().(PointerFieldAccess).getTarget().getName()="debug_level"
		and target_2.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viocp_791
		and target_2.getRightOperand().(Literal).getValue()="131072"
		and target_2.getParent().(IfStmt).getThen() instanceof ExprStmt)
}

predicate func_3(Variable viocp_791) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="name"
		and target_3.getQualifier().(VariableAccess).getTarget()=viocp_791
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_4(Function func) {
	exists(DeclStmt target_4 |
		target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

predicate func_5(Variable viocp_791, Parameter vioc_787, Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("mpt_verify_adapter")
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vioc_787
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=viocp_791
		and target_5.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="7mptctlioctl_fwdl - ioc%d not found!\n"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vioc_787
		and target_5.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-19"
		and target_5.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and target_5.getElse().(BlockStmt).getStmt(0) instanceof IfStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

predicate func_8(Parameter vioc_787) {
	exists(IfStmt target_8 |
		target_8.getCondition() instanceof BitwiseAndExpr
		and target_8.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_8.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="7mptctl: %s: DbG: kfwdl.ioc   = %04xh\n"
		and target_8.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof PointerFieldAccess
		and target_8.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vioc_787)
}

predicate func_9(Function func) {
	exists(EmptyStmt target_9 |
		target_9.toString() = ";"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9)
}

from Function func, Variable vn_801, Variable vmptctl_id, Parameter vufwbuf_787, Variable vmf_790, Variable viocp_791, Parameter vioc_787
where
func_0(vn_801, vufwbuf_787, viocp_791)
and func_1(vmptctl_id, vmf_790, viocp_791)
and func_2(viocp_791)
and func_3(viocp_791)
and func_4(func)
and func_5(viocp_791, vioc_787, func)
and func_8(vioc_787)
and func_9(func)
and vn_801.getType().hasName("int")
and vmptctl_id.getType().hasName("u8")
and vufwbuf_787.getType().hasName("char *")
and vmf_790.getType().hasName("MPT_FRAME_HDR *")
and viocp_791.getType().hasName("MPT_ADAPTER *")
and vioc_787.getType().hasName("int")
and vn_801.getParentScope+() = func
and not vmptctl_id.getParentScope+() = func
and vufwbuf_787.getParentScope+() = func
and vmf_790.getParentScope+() = func
and viocp_791.getParentScope+() = func
and vioc_787.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
