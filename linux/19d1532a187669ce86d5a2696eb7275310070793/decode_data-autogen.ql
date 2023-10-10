/**
 * @name linux-19d1532a187669ce86d5a2696eb7275310070793-decode_data
 * @id cpp/linux/19d1532a187669ce86d5a2696eb7275310070793/decode_data
 * @description linux-19d1532a187669ce86d5a2696eb7275310070793-decode_data 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vsp_820, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="rx_count_cooked"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_820
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SizeofExprOperator).getValue()="400"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getTarget().getName()="cooked_buf"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_820
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="36pack: cooked buffer overrun, data loss\n"
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(2) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_2(Parameter vsp_820, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rx_count"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_820
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_2))
}

predicate func_3(Function func) {
	exists(ReturnStmt target_3 |
		target_3.toString() = "return ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_3))
}

predicate func_6(Parameter vsp_820) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="rx_count"
		and target_6.getQualifier().(VariableAccess).getTarget()=vsp_820)
}

predicate func_7(Parameter vsp_820) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="rx_count_cooked"
		and target_7.getQualifier().(VariableAccess).getTarget()=vsp_820)
}

from Function func, Parameter vsp_820
where
not func_0(vsp_820, func)
and not func_2(vsp_820, func)
and not func_3(func)
and vsp_820.getType().hasName("sixpack *")
and func_6(vsp_820)
and func_7(vsp_820)
and vsp_820.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
