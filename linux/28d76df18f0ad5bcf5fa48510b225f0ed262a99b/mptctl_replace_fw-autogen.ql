/**
 * @name linux-28d76df18f0ad5bcf5fa48510b225f0ed262a99b-mptctl_replace_fw
 * @id cpp/linux/28d76df18f0ad5bcf5fa48510b225f0ed262a99b/mptctl_replace_fw
 * @description linux-28d76df18f0ad5bcf5fa48510b225f0ed262a99b-mptctl_replace_fw 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vuarg_1717) {
	exists(Literal target_0 |
		target_0.getValue()="1726"
		and not target_0.getValue()="1653"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3mptctl%s@%d::mptctl_replace_fw - Unable to read in mpt_ioctl_replace_fw struct @ %p\n"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="drivers/message/fusion/mptctl.c"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vuarg_1717)
}

predicate func_1(Variable vuarg_1717, Variable vioc_1719) {
	exists(Literal target_1 |
		target_1.getValue()="1759"
		and not target_1.getValue()="1679"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3mptctl: %s: ERROR - %s@%d::mptctl_replace_fw - Unable to read in mpt_ioctl_replace_fw image @ %p\n"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vioc_1719
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="drivers/message/fusion/mptctl.c"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vuarg_1717)
}

predicate func_2(Function func) {
	exists(DeclStmt target_2 |
		target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Function func) {
	exists(DeclStmt target_3 |
		func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Variable vkarg_1718, Variable vioc_1719, Variable viocnum_1720, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=viocnum_1720
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mpt_verify_adapter")
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="iocnum"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="hdr"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vkarg_1718
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vioc_1719
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vioc_1719
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="7mptctl%s::mptctl_replace_fw() @%d - ioc%d not found!\n"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="drivers/message/fusion/mptctl.c"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1733"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=viocnum_1720
		and target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-19"
		and target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

from Function func, Variable vuarg_1717, Variable vkarg_1718, Variable vioc_1719, Variable viocnum_1720
where
func_0(vuarg_1717)
and func_1(vuarg_1717, vioc_1719)
and func_2(func)
and func_3(func)
and func_4(vkarg_1718, vioc_1719, viocnum_1720, func)
and vuarg_1717.getType().hasName("mpt_ioctl_replace_fw *")
and vkarg_1718.getType().hasName("mpt_ioctl_replace_fw")
and vioc_1719.getType().hasName("MPT_ADAPTER *")
and viocnum_1720.getType().hasName("int")
and vuarg_1717.getParentScope+() = func
and vkarg_1718.getParentScope+() = func
and vioc_1719.getParentScope+() = func
and viocnum_1720.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
