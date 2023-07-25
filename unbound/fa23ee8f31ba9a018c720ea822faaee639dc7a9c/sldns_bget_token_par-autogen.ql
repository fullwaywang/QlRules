/**
 * @name unbound-fa23ee8f31ba9a018c720ea822faaee639dc7a9c-sldns_bget_token_par
 * @id cpp/unbound/fa23ee8f31ba9a018c720ea822faaee639dc7a9c/sldns-bget-token-par
 * @description unbound-fa23ee8f31ba9a018c720ea822faaee639dc7a9c-sldns/parse.c-sldns_bget_token_par CVE-2019-25035
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtoken_243, Parameter vlimit_244, Variable vt_249, Variable vi_250, ExprStmt target_3, LogicalAndExpr target_4, ExprStmt target_2, ExprStmt target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlimit_244
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_250
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_244
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vt_249
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vtoken_243
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_244
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vt_249
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getLocation())
		and target_5.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vtoken_243, Parameter vlimit_244, Variable vt_249, Variable vi_250, IfStmt target_1) {
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlimit_244
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_250
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_244
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vt_249
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vtoken_243
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_244
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vt_249
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_2(Variable vt_249, NotExpr target_6, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vt_249
		and target_2.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="32"
		and target_2.getParent().(IfStmt).getCondition()=target_6
}

predicate func_3(Parameter vtoken_243, Variable vt_249, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vt_249
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vtoken_243
}

predicate func_4(Parameter vtoken_243, Parameter vlimit_244, Variable vt_249, Variable vi_250, LogicalAndExpr target_4) {
		target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlimit_244
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vi_250
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_244
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vt_249
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vtoken_243
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit_244
}

predicate func_5(Variable vi_250, ExprStmt target_5) {
		target_5.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_250
}

predicate func_6(NotExpr target_6) {
		target_6.getOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("strchr")
		and target_6.getOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("strchr")
		and target_6.getOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(CharLiteral).getValue()="32"
}

from Function func, Parameter vtoken_243, Parameter vlimit_244, Variable vt_249, Variable vi_250, IfStmt target_1, ExprStmt target_2, ExprStmt target_3, LogicalAndExpr target_4, ExprStmt target_5, NotExpr target_6
where
not func_0(vtoken_243, vlimit_244, vt_249, vi_250, target_3, target_4, target_2, target_5)
and func_1(vtoken_243, vlimit_244, vt_249, vi_250, target_1)
and func_2(vt_249, target_6, target_2)
and func_3(vtoken_243, vt_249, target_3)
and func_4(vtoken_243, vlimit_244, vt_249, vi_250, target_4)
and func_5(vi_250, target_5)
and func_6(target_6)
and vtoken_243.getType().hasName("char *")
and vlimit_244.getType().hasName("size_t")
and vt_249.getType().hasName("char *")
and vi_250.getType().hasName("size_t")
and vtoken_243.getParentScope+() = func
and vlimit_244.getParentScope+() = func
and vt_249.getParentScope+() = func
and vi_250.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
