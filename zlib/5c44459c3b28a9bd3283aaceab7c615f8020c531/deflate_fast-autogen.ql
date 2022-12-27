/**
 * @name zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflate_fast
 * @id cpp/zlib/5c44459c3b28a9bd3283aaceab7c615f8020c531/deflate-fast
 * @description zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflate_fast CVE-2018-25032
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

predicate func_10(Function func) {
	exists(Literal target_10 |
		target_10.getValue()="1"
		and not target_10.getValue()="8"
		and target_10.getParent().(SubExpr).getParent().(EQExpr).getAnOperand() instanceof SubExpr
		and target_10.getEnclosingFunction() = func)
}

predicate func_12(Parameter vs_0, Variable vdist_1880) {
	exists(AssignExpr target_12 |
		target_12.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_12.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_12.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_12.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_12.getRValue().(VariableAccess).getTarget()=vdist_1880)
}

predicate func_13(Parameter vs_0, Variable vdist_1880) {
	exists(AssignExpr target_13 |
		target_13.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_13.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_13.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_13.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_13.getRValue().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vdist_1880
		and target_13.getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8")
}

predicate func_14(Parameter vs_0) {
	exists(AssignExpr target_14 |
		target_14.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_14.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_14.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_14.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_14.getRValue() instanceof Literal)
}

predicate func_15(Parameter vs_0) {
	exists(ExprStmt target_15 |
		target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_15.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0")
}

predicate func_16(Parameter vs_0, Variable vbflush_1842) {
	exists(ExprStmt target_16 |
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbflush_1842
		and target_16.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_16.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_16.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sym_end"
		and target_16.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0)
}

predicate func_20(Function func) {
	exists(Literal target_20 |
		target_20.getValue()="0"
		and target_20.getEnclosingFunction() = func)
}

predicate func_22(Parameter vs_0, Variable vdist_1880) {
	exists(AssignExpr target_22 |
		target_22.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_22.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_22.getLValue().(ArrayExpr).getArrayOffset() instanceof PointerFieldAccess
		and target_22.getRValue().(VariableAccess).getTarget()=vdist_1880)
}

predicate func_23(Function func) {
	exists(SubExpr target_23 |
		target_23.getLeftOperand() instanceof PointerFieldAccess
		and target_23.getRightOperand() instanceof Literal
		and target_23.getEnclosingFunction() = func)
}

predicate func_24(Parameter vs_0) {
	exists(AssignExpr target_24 |
		target_24.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_24.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_24.getLValue().(ArrayExpr).getArrayOffset() instanceof PointerFieldAccess
		and target_24.getRValue() instanceof Literal)
}

predicate func_26(Parameter vs_0) {
	exists(PointerFieldAccess target_26 |
		target_26.getTarget().getName()="dyn_dtree"
		and target_26.getQualifier().(VariableAccess).getTarget()=vs_0)
}

predicate func_28(Parameter vs_0) {
	exists(PointerFieldAccess target_28 |
		target_28.getTarget().getName()="dyn_ltree"
		and target_28.getQualifier().(VariableAccess).getTarget()=vs_0)
}

predicate func_29(Variable vdist_1880) {
	exists(BinaryBitwiseOperation target_29 |
		target_29.getLeftOperand().(VariableAccess).getTarget()=vdist_1880
		and target_29.getRightOperand().(Literal).getValue()="7")
}

from Function func, Parameter vs_0, Variable vbflush_1842, Variable vdist_1880
where
func_0(vs_0)
and func_1(vs_0)
and func_2(vs_0)
and func_4(vs_0)
and func_10(func)
and not func_12(vs_0, vdist_1880)
and not func_13(vs_0, vdist_1880)
and not func_14(vs_0)
and not func_15(vs_0)
and not func_16(vs_0, vbflush_1842)
and func_20(func)
and func_22(vs_0, vdist_1880)
and func_23(func)
and func_24(vs_0)
and vs_0.getType().hasName("deflate_state *")
and func_26(vs_0)
and func_28(vs_0)
and vbflush_1842.getType().hasName("int")
and vdist_1880.getType().hasName("ush")
and func_29(vdist_1880)
and vs_0.getParentScope+() = func
and vbflush_1842.getParentScope+() = func
and vdist_1880.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
