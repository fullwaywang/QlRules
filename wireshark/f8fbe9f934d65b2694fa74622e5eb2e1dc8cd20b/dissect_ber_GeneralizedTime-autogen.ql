/**
 * @name wireshark-f8fbe9f934d65b2694fa74622e5eb2e1dc8cd20b-dissect_ber_GeneralizedTime
 * @id cpp/wireshark/f8fbe9f934d65b2694fa74622e5eb2e1dc8cd20b/dissect-ber-GeneralizedTime
 * @description wireshark-f8fbe9f934d65b2694fa74622e5eb2e1dc8cd20b-epan/dissectors/packet-ber.c-dissect_ber_GeneralizedTime CVE-2019-9209
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfirst_digits_3605, BlockStmt target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vfirst_digits_3605
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vfirst_digits_3605
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="999"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation()))
}

predicate func_1(Variable vret_3608, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=vret_3608
		and target_1.getAnOperand().(Literal).getValue()="2"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_2.getStmt(0).(GotoStmt).getName() ="invalid"
}

predicate func_3(Variable vfirst_digits_3605, ExprStmt target_3) {
		target_3.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getTarget().hasName("g_snprintf")
		and target_3.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="5"
		and target_3.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%c%.3d"
		and target_3.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(3).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getExpr().(AssignPointerAddExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vfirst_digits_3605
}

predicate func_4(Variable vfirst_digits_3605, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("g_snprintf")
		and target_4.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="12"
		and target_4.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()=" (UTC%c%.4d)"
		and target_4.getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_4.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vfirst_digits_3605
}

from Function func, Variable vfirst_digits_3605, Variable vret_3608, EqualityOperation target_1, BlockStmt target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vfirst_digits_3605, target_2, target_3, target_4)
and func_1(vret_3608, target_2, target_1)
and func_2(target_2)
and func_3(vfirst_digits_3605, target_3)
and func_4(vfirst_digits_3605, target_4)
and vfirst_digits_3605.getType().hasName("int")
and vret_3608.getType().hasName("int")
and vfirst_digits_3605.getParentScope+() = func
and vret_3608.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
