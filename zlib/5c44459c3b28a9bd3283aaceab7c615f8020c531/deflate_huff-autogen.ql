/**
 * @name zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflate_huff
 * @id cpp/zlib/5c44459c3b28a9bd3283aaceab7c615f8020c531/deflate-huff
 * @description zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflate_huff CVE-2018-25032
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_0) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="last_lit"
		and target_0.getQualifier().(VariableAccess).getTarget()=vs_0)
}

predicate func_1(Parameter vs_0) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="l_buf"
		and target_1.getQualifier().(VariableAccess).getTarget()=vs_0)
}

predicate func_2(Parameter vs_0) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="last_lit"
		and target_2.getQualifier().(VariableAccess).getTarget()=vs_0)
}

predicate func_4(Parameter vs_0) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="lit_bufsize"
		and target_4.getQualifier().(VariableAccess).getTarget()=vs_0)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="1"
		and not target_6.getValue()="0"
		and target_6.getParent().(SubExpr).getParent().(EQExpr).getAnOperand() instanceof SubExpr
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Parameter vs_0) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_7.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_7.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_7.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_7.getRValue() instanceof Literal)
}

predicate func_9(Variable vbflush_2147, Parameter vs_0) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbflush_2147
		and target_9.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_9.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_9.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sym_end"
		and target_9.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0)
}

predicate func_11(Function func) {
	exists(Literal target_11 |
		target_11.getValue()="0"
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(Parameter vs_0) {
	exists(AssignExpr target_12 |
		target_12.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_12.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_12.getLValue().(ArrayExpr).getArrayOffset() instanceof PointerFieldAccess
		and target_12.getRValue() instanceof Literal)
}

predicate func_13(Function func) {
	exists(SubExpr target_13 |
		target_13.getLeftOperand() instanceof PointerFieldAccess
		and target_13.getRightOperand() instanceof Literal
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(Parameter vs_0) {
	exists(PointerFieldAccess target_14 |
		target_14.getTarget().getName()="strstart"
		and target_14.getQualifier().(VariableAccess).getTarget()=vs_0)
}

predicate func_15(Parameter vs_0) {
	exists(PointerFieldAccess target_15 |
		target_15.getTarget().getName()="dyn_ltree"
		and target_15.getQualifier().(VariableAccess).getTarget()=vs_0)
}

from Function func, Variable vbflush_2147, Parameter vs_0
where
func_0(vs_0)
and func_1(vs_0)
and func_2(vs_0)
and func_4(vs_0)
and func_6(func)
and not func_7(vs_0)
and not func_9(vbflush_2147, vs_0)
and func_11(func)
and func_12(vs_0)
and func_13(func)
and vbflush_2147.getType().hasName("int")
and vs_0.getType().hasName("deflate_state *")
and func_14(vs_0)
and func_15(vs_0)
and vbflush_2147.getParentScope+() = func
and vs_0.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
