/**
 * @name linux-28d76df18f0ad5bcf5fa48510b225f0ed262a99b-mptctl_readtest
 * @id cpp/linux/28d76df18f0ad5bcf5fa48510b225f0ed262a99b/mptctl_readtest
 * @description linux-28d76df18f0ad5bcf5fa48510b225f0ed262a99b-mptctl_readtest 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vuarg_1515) {
	exists(Literal target_0 |
		target_0.getValue()="1523"
		and not target_0.getValue()="1485"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3mptctl%s@%d::mptctl_readtest - Unable to read in mpt_ioctl_test struct @ %p\n"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="drivers/message/fusion/mptctl.c"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vuarg_1515)
}

predicate func_1(Variable vuarg_1515, Variable vioc_1517) {
	exists(Literal target_1 |
		target_1.getValue()="1555"
		and not target_1.getValue()="1510"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3mptctl: %s: ERROR - %s@%d::mptctl_readtest - Unable to write out mpt_ioctl_test struct @ %p\n"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vioc_1517
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="drivers/message/fusion/mptctl.c"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vuarg_1515)
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

predicate func_4(Variable vkarg_1516, Variable vioc_1517, Variable viocnum_1518, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=viocnum_1518
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mpt_verify_adapter")
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="iocnum"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="hdr"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vkarg_1516
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vioc_1517
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vioc_1517
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="7mptctl%s::mptctl_readtest() @%d - ioc%d not found!\n"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="drivers/message/fusion/mptctl.c"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1530"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=viocnum_1518
		and target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-19"
		and target_4.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

from Function func, Variable vuarg_1515, Variable vkarg_1516, Variable vioc_1517, Variable viocnum_1518
where
func_0(vuarg_1515)
and func_1(vuarg_1515, vioc_1517)
and func_2(func)
and func_3(func)
and func_4(vkarg_1516, vioc_1517, viocnum_1518, func)
and vuarg_1515.getType().hasName("mpt_ioctl_test *")
and vkarg_1516.getType().hasName("mpt_ioctl_test")
and vioc_1517.getType().hasName("MPT_ADAPTER *")
and viocnum_1518.getType().hasName("int")
and vuarg_1515.getParentScope+() = func
and vkarg_1516.getParentScope+() = func
and vioc_1517.getParentScope+() = func
and viocnum_1518.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
