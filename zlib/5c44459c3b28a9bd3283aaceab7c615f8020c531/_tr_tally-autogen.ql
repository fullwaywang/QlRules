/**
 * @name zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-_tr_tally
 * @id cpp/zlib/5c44459c3b28a9bd3283aaceab7c615f8020c531/-tr-tally
 * @description zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-_tr_tally CVE-2018-25032
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

predicate func_3(Parameter vlc_0, Parameter vs_0) {
	exists(VariableAccess target_3 |
		target_3.getTarget()=vlc_0
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="l_buf"
		and target_3.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_3.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="last_lit"
		and target_3.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="1"
		and not target_5.getValue()="8"
		and target_5.getParent().(SubExpr).getParent().(EQExpr).getAnOperand() instanceof SubExpr
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Parameter vdist_0, Parameter vs_0) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_6.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_6.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_6.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_6.getRValue().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vdist_0
		and target_6.getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8")
}

predicate func_7(Parameter vlc_0, Parameter vs_0, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlc_0
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_7))
}

predicate func_11(Parameter vdist_0, Parameter vs_0) {
	exists(AssignExpr target_11 |
		target_11.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_11.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_11.getLValue().(ArrayExpr).getArrayOffset() instanceof PointerFieldAccess
		and target_11.getRValue().(VariableAccess).getTarget()=vdist_0)
}

predicate func_12(Parameter vs_0) {
	exists(SubExpr target_12 |
		target_12.getLeftOperand().(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_12.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_12.getRightOperand() instanceof Literal)
}

predicate func_13(Parameter vlc_0) {
	exists(AssignExpr target_13 |
		target_13.getLValue().(ArrayExpr).getArrayBase() instanceof PointerFieldAccess
		and target_13.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand() instanceof PointerFieldAccess
		and target_13.getRValue().(VariableAccess).getTarget()=vlc_0)
}

from Function func, Parameter vdist_0, Parameter vlc_0, Parameter vs_0
where
func_0(vs_0)
and func_3(vlc_0, vs_0)
and func_5(func)
and not func_6(vdist_0, vs_0)
and not func_7(vlc_0, vs_0, func)
and func_11(vdist_0, vs_0)
and func_12(vs_0)
and vdist_0.getType().hasName("unsigned int")
and vlc_0.getType().hasName("unsigned int")
and func_13(vlc_0)
and vs_0.getType().hasName("deflate_state *")
and vdist_0.getParentScope+() = func
and vlc_0.getParentScope+() = func
and vs_0.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
