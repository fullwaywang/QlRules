/**
 * @name linux-28d76df18f0ad5bcf5fa48510b225f0ed262a99b-mptctl_do_reset
 * @id cpp/linux/28d76df18f0ad5bcf5fa48510b225f0ed262a99b/mptctl_do_reset
 * @description linux-28d76df18f0ad5bcf5fa48510b225f0ed262a99b-mptctl_do_reset 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vurinfo_710) {
	exists(Literal target_0 |
		target_0.getValue()="717"
		and not target_0.getValue()="716"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3mptctl%s@%d::mptctl_do_reset - Unable to copy mpt_ioctl_diag_reset struct @ %p\n"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="drivers/message/fusion/mptctl.c"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vurinfo_710)
}

predicate func_1(Variable viocp_712) {
	exists(Literal target_1 |
		target_1.getValue()="732"
		and not target_1.getValue()="725"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3mptctl: %s: ERROR - %s@%d::mptctl_do_reset - reset failed.\n"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viocp_712
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="drivers/message/fusion/mptctl.c")
}

predicate func_2(Function func) {
	exists(DeclStmt target_2 |
		target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Variable vkrinfo_711, Variable viocp_712, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("mpt_verify_adapter")
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="iocnum"
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="hdr"
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vkrinfo_711
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=viocp_712
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="7mptctl%s@%d::mptctl_do_reset - ioc%d not found!\n"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="drivers/message/fusion/mptctl.c"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="723"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="iocnum"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="hdr"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vkrinfo_711
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-19"
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

from Function func, Variable vurinfo_710, Variable vkrinfo_711, Variable viocp_712
where
func_0(vurinfo_710)
and func_1(viocp_712)
and func_2(func)
and func_3(vkrinfo_711, viocp_712, func)
and vurinfo_710.getType().hasName("mpt_ioctl_diag_reset *")
and vkrinfo_711.getType().hasName("mpt_ioctl_diag_reset")
and viocp_712.getType().hasName("MPT_ADAPTER *")
and vurinfo_710.getParentScope+() = func
and vkrinfo_711.getParentScope+() = func
and viocp_712.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
