/**
 * @name opensc-5df913b7-insert_pin
 * @id cpp/opensc/5df913b7/insert-pin
 * @description opensc-5df913b7-src/libopensc/pkcs15-tcos.c-insert_pin CVE-2021-42780
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vr_206, ContinueStmt target_6, RelationalOperation target_7) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vr_206
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2"
		and target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(IfStmt).getThen()=target_6
		and target_7.getGreaterOperand().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vr_206, Variable vi_230, BlockStmt target_8, ExprStmt target_9, RelationalOperation target_4) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand() instanceof RelationalOperation
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_230
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vr_206
		and target_1.getParent().(ForStmt).getStmt()=target_8
		and target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vr_206, Variable vbuf_229, Variable vi_230, BlockStmt target_10, RelationalOperation target_11, LogicalAndExpr target_12, EqualityOperation target_5) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand() instanceof EqualityOperation
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_230
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_229
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_230
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vr_206
		and target_2.getParent().(IfStmt).getThen()=target_10
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_11.getLesserOperand().(VariableAccess).getLocation())
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_3(Variable vbuf_229, ContinueStmt target_6, EqualityOperation target_3) {
		target_3.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_229
		and target_3.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getAnOperand().(HexLiteral).getValue()="160"
		and target_3.getParent().(IfStmt).getThen()=target_6
}

predicate func_4(Variable vbuf_229, Variable vi_230, BlockStmt target_8, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vi_230
		and target_4.getGreaterOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_229
		and target_4.getGreaterOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_4.getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_4.getParent().(ForStmt).getStmt()=target_8
}

predicate func_5(Variable vbuf_229, Variable vi_230, BlockStmt target_10, EqualityOperation target_5) {
		target_5.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_229
		and target_5.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_230
		and target_5.getAnOperand().(HexLiteral).getValue()="144"
		and target_5.getParent().(IfStmt).getThen()=target_10
}

predicate func_6(ContinueStmt target_6) {
		target_6.toString() = "continue;"
}

predicate func_7(Variable vr_206, Variable vbuf_229, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getGreaterOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_206
		and target_7.getGreaterOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sc_read_record")
		and target_7.getGreaterOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuf_229
		and target_7.getGreaterOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(SizeofExprOperator).getValue()="256"
		and target_7.getGreaterOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="256"
		and target_7.getLesserOperand().(Literal).getValue()="0"
}

predicate func_8(Variable vbuf_229, Variable vi_230, BlockStmt target_8) {
		target_8.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_229
		and target_8.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_230
		and target_8.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="131"
		and target_8.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_229
		and target_8.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_8.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_229
		and target_8.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_230
		and target_8.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="2"
}

predicate func_9(Variable vi_230, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_230
		and target_9.getExpr().(AssignExpr).getRValue().(Literal).getValue()="2"
}

predicate func_10(Variable vbuf_229, Variable vi_230, BlockStmt target_10) {
		target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_229
		and target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_230
		and target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_10.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_229
}

predicate func_11(Variable vr_206, RelationalOperation target_11) {
		 (target_11 instanceof GEExpr or target_11 instanceof LEExpr)
		and target_11.getLesserOperand().(VariableAccess).getTarget()=vr_206
		and target_11.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_12(Variable vbuf_229, Variable vi_230, LogicalAndExpr target_12) {
		target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_229
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_230
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="131"
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_229
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_230
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_12.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_12.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_229
		and target_12.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_230
		and target_12.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="2"
}

from Function func, Variable vr_206, Variable vbuf_229, Variable vi_230, EqualityOperation target_3, RelationalOperation target_4, EqualityOperation target_5, ContinueStmt target_6, RelationalOperation target_7, BlockStmt target_8, ExprStmt target_9, BlockStmt target_10, RelationalOperation target_11, LogicalAndExpr target_12
where
not func_0(vr_206, target_6, target_7)
and not func_1(vr_206, vi_230, target_8, target_9, target_4)
and not func_2(vr_206, vbuf_229, vi_230, target_10, target_11, target_12, target_5)
and func_3(vbuf_229, target_6, target_3)
and func_4(vbuf_229, vi_230, target_8, target_4)
and func_5(vbuf_229, vi_230, target_10, target_5)
and func_6(target_6)
and func_7(vr_206, vbuf_229, target_7)
and func_8(vbuf_229, vi_230, target_8)
and func_9(vi_230, target_9)
and func_10(vbuf_229, vi_230, target_10)
and func_11(vr_206, target_11)
and func_12(vbuf_229, vi_230, target_12)
and vr_206.getType().hasName("int")
and vbuf_229.getType().hasName("unsigned char[256]")
and vi_230.getType().hasName("int")
and vr_206.getParentScope+() = func
and vbuf_229.getParentScope+() = func
and vi_230.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
