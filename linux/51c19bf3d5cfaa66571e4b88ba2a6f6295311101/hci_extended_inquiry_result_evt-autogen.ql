/**
 * @name linux-51c19bf3d5cfaa66571e4b88ba2a6f6295311101-hci_extended_inquiry_result_evt
 * @id cpp/linux/51c19bf3d5cfaa66571e4b88ba2a6f6295311101/hci_extended_inquiry_result_evt
 * @description linux-51c19bf3d5cfaa66571e4b88ba2a6f6295311101-hci_extended_inquiry_result_evt 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vskb_4369, Variable vinfo_4372, Variable vnum_rsp_4373) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof NotExpr
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vskb_4369
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vnum_rsp_4373
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vinfo_4372
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).toString() = "return ...")
}

predicate func_1(Variable vnum_rsp_4373) {
	exists(NotExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vnum_rsp_4373
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).toString() = "return ...")
}

predicate func_2(Parameter vskb_4369) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="data"
		and target_2.getQualifier().(VariableAccess).getTarget()=vskb_4369)
}

predicate func_3(Variable vnum_rsp_4373, Variable v__UNIQUE_ID_ddebug835_4376, Parameter vhdev_4368) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("__dynamic_pr_debug")
		and target_3.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=v__UNIQUE_ID_ddebug835_4376
		and target_3.getArgument(1).(StringLiteral).getValue()="%s num_rsp %d\n"
		and target_3.getArgument(2).(PointerFieldAccess).getTarget().getName()="name"
		and target_3.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhdev_4368
		and target_3.getArgument(3).(VariableAccess).getTarget()=vnum_rsp_4373)
}

from Function func, Parameter vskb_4369, Variable vinfo_4372, Variable vnum_rsp_4373, Variable v__UNIQUE_ID_ddebug835_4376, Parameter vhdev_4368
where
not func_0(vskb_4369, vinfo_4372, vnum_rsp_4373)
and func_1(vnum_rsp_4373)
and vskb_4369.getType().hasName("sk_buff *")
and func_2(vskb_4369)
and vinfo_4372.getType().hasName("extended_inquiry_info *")
and vnum_rsp_4373.getType().hasName("int")
and func_3(vnum_rsp_4373, v__UNIQUE_ID_ddebug835_4376, vhdev_4368)
and v__UNIQUE_ID_ddebug835_4376.getType().hasName("_ddebug")
and vhdev_4368.getType().hasName("hci_dev *")
and vskb_4369.getParentScope+() = func
and vinfo_4372.getParentScope+() = func
and vnum_rsp_4373.getParentScope+() = func
and v__UNIQUE_ID_ddebug835_4376.getParentScope+() = func
and vhdev_4368.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
