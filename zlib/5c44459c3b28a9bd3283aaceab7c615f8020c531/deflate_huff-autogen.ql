/**
 * @name zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflate_huff
 * @id cpp/zlib/5c44459c3b28a9bd3283aaceab7c615f8020c531/deflate-huff
 * @description zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflate.c-deflate_huff CVE-2018-25032
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_0, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="last_lit"
		and target_0.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_1(Parameter vs_0, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="l_buf"
		and target_1.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_2(Parameter vs_0, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="last_lit"
		and target_2.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_3(Parameter vs_0, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="last_lit"
		and target_3.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_4(Parameter vs_0, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="lit_bufsize"
		and target_4.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_5(Parameter vs_0, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="last_lit"
		and target_5.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_6(Function func, Literal target_6) {
		target_6.getValue()="1"
		and not target_6.getValue()="0"
		and target_6.getParent().(SubExpr).getParent().(EQExpr).getAnOperand() instanceof SubExpr
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Parameter vs_0) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_7.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_7.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_7.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_7.getRValue() instanceof Literal)
}

predicate func_8(Parameter vs_0, ArrayExpr target_15, ExprStmt target_16) {
	exists(AssignExpr target_8 |
		target_8.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_8.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_8.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_8.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_8.getRValue().(Literal).getValue()="0"
		and target_15.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_9(Variable vbflush_2147, Parameter vs_0, IfStmt target_17) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbflush_2147
		and target_9.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_9.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_9.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sym_end"
		and target_9.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_17.getCondition().(VariableAccess).getLocation()))
}

predicate func_10(Parameter vs_0, VariableAccess target_10) {
		target_10.getTarget()=vs_0
}

predicate func_12(Parameter vs_0, AssignExpr target_12) {
		target_12.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_12.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_12.getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="last_lit"
		and target_12.getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_12.getRValue() instanceof Literal
}

predicate func_13(Parameter vs_0, SubExpr target_13) {
		target_13.getLeftOperand().(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_13.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_13.getRightOperand() instanceof Literal
}

predicate func_15(Parameter vs_0, ArrayExpr target_15) {
		target_15.getArrayBase().(PointerFieldAccess).getTarget().getName()="dyn_ltree"
		and target_15.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_16(Variable vbflush_2147, Parameter vs_0, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbflush_2147
		and target_16.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="last_lit"
		and target_16.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_16.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand() instanceof SubExpr
}

predicate func_17(Variable vbflush_2147, Parameter vs_0, IfStmt target_17) {
		target_17.getCondition().(VariableAccess).getTarget()=vbflush_2147
		and target_17.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_tr_flush_block")
		and target_17.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_0
		and target_17.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_17.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="strstart"
		and target_17.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="block_start"
		and target_17.getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
}

from Function func, Variable vbflush_2147, Parameter vs_0, PointerFieldAccess target_0, PointerFieldAccess target_1, PointerFieldAccess target_2, PointerFieldAccess target_3, PointerFieldAccess target_4, PointerFieldAccess target_5, Literal target_6, VariableAccess target_10, AssignExpr target_12, SubExpr target_13, ArrayExpr target_15, ExprStmt target_16, IfStmt target_17
where
func_0(vs_0, target_0)
and func_1(vs_0, target_1)
and func_2(vs_0, target_2)
and func_3(vs_0, target_3)
and func_4(vs_0, target_4)
and func_5(vs_0, target_5)
and func_6(func, target_6)
and not func_7(vs_0)
and not func_8(vs_0, target_15, target_16)
and not func_9(vbflush_2147, vs_0, target_17)
and func_10(vs_0, target_10)
and func_12(vs_0, target_12)
and func_13(vs_0, target_13)
and func_15(vs_0, target_15)
and func_16(vbflush_2147, vs_0, target_16)
and func_17(vbflush_2147, vs_0, target_17)
and vbflush_2147.getType().hasName("int")
and vs_0.getType().hasName("deflate_state *")
and vbflush_2147.getParentScope+() = func
and vs_0.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
