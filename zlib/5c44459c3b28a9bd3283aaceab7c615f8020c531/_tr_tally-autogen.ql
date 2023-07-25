/**
 * @name zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-_tr_tally
 * @id cpp/zlib/5c44459c3b28a9bd3283aaceab7c615f8020c531/-tr-tally
 * @description zlib-5c44459c3b28a9bd3283aaceab7c615f8020c531-trees.c-_tr_tally CVE-2018-25032
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_0, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="last_lit"
		and target_0.getQualifier().(VariableAccess).getTarget()=vs_0
}

/*predicate func_1(Parameter vs_0, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="l_buf"
		and target_1.getQualifier().(VariableAccess).getTarget()=vs_0
}

*/
/*predicate func_2(Parameter vs_0, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="last_lit"
		and target_2.getQualifier().(VariableAccess).getTarget()=vs_0
}

*/
predicate func_3(Parameter vlc_0, Parameter vs_0, VariableAccess target_3) {
		target_3.getTarget()=vlc_0
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="l_buf"
		and target_3.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_3.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="last_lit"
		and target_3.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_4(Parameter vs_0, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="last_lit"
		and target_4.getQualifier().(VariableAccess).getTarget()=vs_0
}

predicate func_5(Function func, Literal target_5) {
		target_5.getValue()="1"
		and not target_5.getValue()="8"
		and target_5.getParent().(SubExpr).getParent().(EQExpr).getAnOperand() instanceof SubExpr
		and target_5.getEnclosingFunction() = func
}

predicate func_6(Parameter vdist_0, Parameter vs_0, EqualityOperation target_14) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_6.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_6.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_6.getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_6.getRValue().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vdist_0
		and target_6.getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_6.getRValue().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_14.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vlc_0, Parameter vs_0, ExprStmt target_15, ArrayExpr target_16, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sym_buf"
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sym_next"
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlc_0
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_7)
		and target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_16.getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_8(Parameter vs_0, VariableAccess target_8) {
		target_8.getTarget()=vs_0
}

predicate func_9(Parameter vs_0, VariableAccess target_9) {
		target_9.getTarget()=vs_0
}

predicate func_10(Parameter vdist_0, VariableAccess target_10) {
		target_10.getTarget()=vdist_0
		and target_10.getParent().(AssignExpr).getRValue() = target_10
		and target_10.getParent().(AssignExpr).getLValue() instanceof ArrayExpr
}

predicate func_11(Parameter vdist_0, Parameter vs_0, AssignExpr target_11) {
		target_11.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="d_buf"
		and target_11.getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_11.getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="last_lit"
		and target_11.getLValue().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_11.getRValue().(VariableAccess).getTarget()=vdist_0
}

predicate func_12(Parameter vs_0, SubExpr target_12) {
		target_12.getLeftOperand().(PointerFieldAccess).getTarget().getName()="lit_bufsize"
		and target_12.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_12.getRightOperand() instanceof Literal
}

predicate func_14(Parameter vdist_0, EqualityOperation target_14) {
		target_14.getAnOperand().(VariableAccess).getTarget()=vdist_0
		and target_14.getAnOperand().(Literal).getValue()="0"
}

predicate func_15(Parameter vlc_0, Parameter vs_0, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="l_buf"
		and target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="last_lit"
		and target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlc_0
}

predicate func_16(Parameter vlc_0, Parameter vs_0, ArrayExpr target_16) {
		target_16.getArrayBase().(PointerFieldAccess).getTarget().getName()="dyn_ltree"
		and target_16.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_0
		and target_16.getArrayOffset().(VariableAccess).getTarget()=vlc_0
}

from Function func, Parameter vdist_0, Parameter vlc_0, Parameter vs_0, PointerFieldAccess target_0, VariableAccess target_3, PointerFieldAccess target_4, Literal target_5, VariableAccess target_8, VariableAccess target_9, VariableAccess target_10, AssignExpr target_11, SubExpr target_12, EqualityOperation target_14, ExprStmt target_15, ArrayExpr target_16
where
func_0(vs_0, target_0)
and func_3(vlc_0, vs_0, target_3)
and func_4(vs_0, target_4)
and func_5(func, target_5)
and not func_6(vdist_0, vs_0, target_14)
and not func_7(vlc_0, vs_0, target_15, target_16, func)
and func_8(vs_0, target_8)
and func_9(vs_0, target_9)
and func_10(vdist_0, target_10)
and func_11(vdist_0, vs_0, target_11)
and func_12(vs_0, target_12)
and func_14(vdist_0, target_14)
and func_15(vlc_0, vs_0, target_15)
and func_16(vlc_0, vs_0, target_16)
and vdist_0.getType().hasName("unsigned int")
and vlc_0.getType().hasName("unsigned int")
and vs_0.getType().hasName("deflate_state *")
and vdist_0.getParentScope+() = func
and vlc_0.getParentScope+() = func
and vs_0.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
