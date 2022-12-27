/**
 * @name zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflate_slow
 * @id cpp/zlib/5c44459c3b28a9bd3283aaceab7c615f8020c531/deflate-slow
 * @description zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-deflate_slow CVE-2018-25032
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

predicate func_14(Function func) {
	exists(Literal target_14 |
		target_14.getValue()="1"
		and not target_14.getValue()="8"
		and target_14.getParent().(SubExpr).getParent().(EQExpr).getAnOperand() instanceof SubExpr
		and target_14.getEnclosingFunction() = func)
}

predicate func_17(Parameter vs_0, Variable vdist_2005) {
	exists(AssignExpr target_17 |
		target_17.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_17.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_17.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_17.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_17.getRValue().(VariableAccess).getTarget()=vdist_2005)
}

predicate func_18(Parameter vs_0, Variable vdist_2005) {
	exists(AssignExpr target_18 |
		target_18.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_18.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_18.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_18.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_18.getRValue().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vdist_2005
		and target_18.getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8")
}

predicate func_19(Parameter vs_0) {
	exists(AssignExpr target_19 |
		target_19.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_19.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_19.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_19.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_19.getRValue() instanceof Literal)
}

predicate func_21(Parameter vs_0) {
	exists(ExprStmt target_21 |
		target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_21.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0")
}

predicate func_23(Parameter vs_0, Variable vbflush_1944) {
	exists(ExprStmt target_23 |
		target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbflush_1944
		and target_23.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_23.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_23.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="sym_end"
		and target_23.getExpr().(AssignExpr).getRValue().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0)
}

predicate func_27(Function func) {
	exists(Literal target_27 |
		target_27.getValue()="0"
		and target_27.getEnclosingFunction() = func)
}

predicate func_32(Parameter vs_0, Variable vdist_2005) {
	exists(AssignExpr target_32 |
		target_32.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_32.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_32.getLValue().(ArrayExpr).getArrayOffset() instanceof PointerFieldAccess
		and target_32.getRValue().(VariableAccess).getTarget()=vdist_2005)
}

predicate func_33(Function func) {
	exists(SubExpr target_33 |
		target_33.getLeftOperand() instanceof PointerFieldAccess
		and target_33.getRightOperand() instanceof Literal
		and target_33.getEnclosingFunction() = func)
}

predicate func_34(Parameter vs_0) {
	exists(AssignExpr target_34 |
		target_34.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_34.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_34.getLValue().(ArrayExpr).getArrayOffset() instanceof PointerFieldAccess
		and target_34.getRValue() instanceof Literal)
}

predicate func_39(Parameter vs_0) {
	exists(PointerFieldAccess target_39 |
		target_39.getTarget().getName()="dyn_ltree"
		and target_39.getQualifier().(VariableAccess).getTarget()=vs_0)
}

predicate func_40(Parameter vs_0) {
	exists(PointerFieldAccess target_40 |
		target_40.getTarget().getName()="strstart"
		and target_40.getQualifier().(VariableAccess).getTarget()=vs_0)
}

predicate func_41(Variable vdist_2005) {
	exists(BinaryBitwiseOperation target_41 |
		target_41.getLeftOperand().(VariableAccess).getTarget()=vdist_2005
		and target_41.getRightOperand().(Literal).getValue()="7")
}

from Function func, Parameter vs_0, Variable vbflush_1944, Variable vdist_2005
where
func_0(vs_0)
and func_1(vs_0)
and func_2(vs_0)
and func_4(vs_0)
and func_14(func)
and not func_17(vs_0, vdist_2005)
and not func_18(vs_0, vdist_2005)
and not func_19(vs_0)
and not func_21(vs_0)
and not func_23(vs_0, vbflush_1944)
and func_27(func)
and func_32(vs_0, vdist_2005)
and func_33(func)
and func_34(vs_0)
and vs_0.getType().hasName("deflate_state *")
and func_39(vs_0)
and func_40(vs_0)
and vbflush_1944.getType().hasName("int")
and vdist_2005.getType().hasName("ush")
and func_41(vdist_2005)
and vs_0.getParentScope+() = func
and vbflush_1944.getParentScope+() = func
and vdist_2005.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
