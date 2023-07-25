/**
 * @name wireshark-cd09cb5cfb673beca3cce20b1d6a9bc67a134ae1-get_t61_string
 * @id cpp/wireshark/cd09cb5cfb673beca3cce20b1d6a9bc67a134ae1/get-t61-string
 * @description wireshark-cd09cb5cfb673beca3cce20b1d6a9bc67a134ae1-epan/charsets.c-get_t61_string CVE-2019-5718
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlength_1374, Variable vi_1376, BlockStmt target_2, RelationalOperation target_3, CommaExpr target_4, ExprStmt target_5) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_1376
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlength_1374
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_4.getRightOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vc_1377, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vc_1377
		and target_1.getAnOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="240"
		and target_1.getAnOperand().(HexLiteral).getValue()="192"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vc_1377, BlockStmt target_2) {
		target_2.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vc_1377
		and target_2.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_2.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vc_1377
		and target_2.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_2.getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="32"
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("wmem_strbuf_append_unichar")
		and target_2.getStmt(1).(IfStmt).getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(ArrayExpr).getArrayOffset().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="31"
		and target_2.getStmt(1).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("wmem_strbuf_append_unichar")
		and target_2.getStmt(1).(IfStmt).getElse().(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("wmem_strbuf_append_unichar")
		and target_2.getStmt(1).(IfStmt).getElse().(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("wmem_strbuf_append_unichar")
}

predicate func_3(Parameter vlength_1374, Variable vi_1376, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vi_1376
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vlength_1374
}

predicate func_4(Variable vi_1376, Variable vc_1377, CommaExpr target_4) {
		target_4.getLeftOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vc_1377
		and target_4.getRightOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_1376
}

predicate func_5(Variable vi_1376, ExprStmt target_5) {
		target_5.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_1376
}

from Function func, Parameter vlength_1374, Variable vi_1376, Variable vc_1377, EqualityOperation target_1, BlockStmt target_2, RelationalOperation target_3, CommaExpr target_4, ExprStmt target_5
where
not func_0(vlength_1374, vi_1376, target_2, target_3, target_4, target_5)
and func_1(vc_1377, target_2, target_1)
and func_2(vc_1377, target_2)
and func_3(vlength_1374, vi_1376, target_3)
and func_4(vi_1376, vc_1377, target_4)
and func_5(vi_1376, target_5)
and vlength_1374.getType().hasName("gint")
and vi_1376.getType().hasName("gint")
and vc_1377.getType().hasName("guint8 *")
and vlength_1374.getParentScope+() = func
and vi_1376.getParentScope+() = func
and vc_1377.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
