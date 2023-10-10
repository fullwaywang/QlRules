/**
 * @name file-46a8443f76cec4b41ec736eca396984c74664f84-cdf_read_property_info
 * @id cpp/file/46a8443f76cec4b41ec736eca396984c74664f84/cdf-read-property-info
 * @description file-46a8443f76cec4b41ec736eca396984c74664f84-src/cdf.c-cdf_read_property_info CVE-2019-18218
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnelements_977, BlockStmt target_3, ExprStmt target_4, EqualityOperation target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnelements_977
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="100000"
		and target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(IfStmt).getThen()=target_3
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vnelements_977, BlockStmt target_3, EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=vnelements_977
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_3
}

predicate func_2(BitwiseAndExpr target_5, Function func, EmptyStmt target_2) {
		target_2.toString() = ";"
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_5
		and target_2.getEnclosingFunction() = func
}

predicate func_3(BlockStmt target_3) {
		target_3.getStmt(0).(EmptyStmt).toString() = ";"
		and target_3.getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_3.getStmt(1).(GotoStmt).getName() ="out"
}

predicate func_4(Variable vnelements_977, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnelements_977
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cdf_getuint32")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="1"
}

predicate func_5(BitwiseAndExpr target_5) {
		target_5.getLeftOperand().(ValueFieldAccess).getTarget().getName()="pi_type"
		and target_5.getRightOperand().(Literal).getValue()="4095"
}

from Function func, Variable vnelements_977, EqualityOperation target_1, EmptyStmt target_2, BlockStmt target_3, ExprStmt target_4, BitwiseAndExpr target_5
where
not func_0(vnelements_977, target_3, target_4, target_1)
and func_1(vnelements_977, target_3, target_1)
and func_2(target_5, func, target_2)
and func_3(target_3)
and func_4(vnelements_977, target_4)
and func_5(target_5)
and vnelements_977.getType().hasName("size_t")
and vnelements_977.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
