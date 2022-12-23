/**
 * @name linux-28d76df18f0ad5bcf5fa48510b225f0ed262a99b-mptctl_getiocinfo
 * @id cpp/linux/28d76df18f0ad5bcf5fa48510b225f0ed262a99b/mptctl_getiocinfo
 * @description linux-28d76df18f0ad5bcf5fa48510b225f0ed262a99b-mptctl_getiocinfo 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vkarg_1244) {
	exists(Literal target_0 |
		target_0.getValue()="1271"
		and not target_0.getValue()="1252"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3mptctl%s@%d::mpt_ioctl_iocinfo() - memdup_user returned error [%ld]\n"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="drivers/message/fusion/mptctl.c"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("PTR_ERR")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vkarg_1244)
}

predicate func_1(Variable vioc_1245) {
	exists(Literal target_1 |
		target_1.getValue()="1287"
		and not target_1.getValue()="1260"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3mptctl: %s: ERROR - %s@%d::mptctl_getiocinfo - Structure size mismatch. Command not completed.\n"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vioc_1245
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="drivers/message/fusion/mptctl.c")
}

predicate func_2(Variable vioc_1245, Variable vuarg_1243) {
	exists(Literal target_2 |
		target_2.getValue()="1368"
		and not target_2.getValue()="1341"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3mptctl: %s: ERROR - %s@%d::mptctl_getiocinfo - Unable to write out mpt_ioctl_iocinfo struct @ %p\n"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vioc_1245
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="drivers/message/fusion/mptctl.c"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vuarg_1243)
}

predicate func_3(Variable vkarg_1244) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="hdr"
		and target_3.getQualifier().(VariableAccess).getTarget()=vkarg_1244)
}

predicate func_4(Variable vkarg_1244) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vkarg_1244
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof LogicalOrExpr)
}

predicate func_6(Function func) {
	exists(DeclStmt target_6 |
		target_6.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

predicate func_7(Function func) {
	exists(DeclStmt target_7 |
		func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

predicate func_8(Variable vioc_1245, Variable viocnum_1247, Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=viocnum_1247
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("mpt_verify_adapter")
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="iocnum"
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vioc_1245
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vioc_1245
		and target_8.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="7mptctl%s::mptctl_getiocinfo() @%d - ioc%d not found!\n"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="drivers/message/fusion/mptctl.c"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1278"
		and target_8.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=viocnum_1247
		and target_8.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_8.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-19"
		and target_8.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

from Function func, Variable vioc_1245, Variable viocnum_1247, Parameter vdata_size_1241, Variable vuarg_1243, Variable vkarg_1244
where
func_0(vkarg_1244)
and func_1(vioc_1245)
and func_2(vioc_1245, vuarg_1243)
and func_3(vkarg_1244)
and func_4(vkarg_1244)
and func_6(func)
and func_7(func)
and func_8(vioc_1245, viocnum_1247, func)
and vioc_1245.getType().hasName("MPT_ADAPTER *")
and viocnum_1247.getType().hasName("int")
and vdata_size_1241.getType().hasName("unsigned int")
and vuarg_1243.getType().hasName("mpt_ioctl_iocinfo *")
and vkarg_1244.getType().hasName("mpt_ioctl_iocinfo *")
and vioc_1245.getParentScope+() = func
and viocnum_1247.getParentScope+() = func
and vdata_size_1241.getParentScope+() = func
and vuarg_1243.getParentScope+() = func
and vkarg_1244.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
