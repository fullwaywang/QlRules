/**
 * @name ffmpeg-07050d7bdc32d82e53ee5bb727f5882323d00dba-filter_frame
 * @id cpp/ffmpeg/07050d7bdc32d82e53ee5bb727f5882323d00dba/filter-frame
 * @description ffmpeg-07050d7bdc32d82e53ee5bb727f5882323d00dba-libavfilter/vf_fieldorder.c-filter_frame CVE-2020-22022
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vh_82, ExprStmt target_4) {
	exists(MulExpr target_0 |
		target_0.getLeftOperand() instanceof ArrayExpr
		and target_0.getRightOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vh_82
		and target_0.getRightOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="2"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getRightOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vh_82, RelationalOperation target_5) {
	exists(MulExpr target_1 |
		target_1.getLeftOperand() instanceof ArrayExpr
		and target_1.getRightOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vh_82
		and target_1.getRightOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="2"
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getRightOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vplane_82, Variable vout_84, ArrayExpr target_2) {
		target_2.getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_84
		and target_2.getArrayOffset().(VariableAccess).getTarget()=vplane_82
		and target_2.getParent().(AssignExpr).getRValue() = target_2
}

predicate func_3(Parameter vframe_77, Variable vplane_82, ArrayExpr target_3) {
		target_3.getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_77
		and target_3.getArrayOffset().(VariableAccess).getTarget()=vplane_82
		and target_3.getParent().(AssignExpr).getRValue() = target_3
}

predicate func_4(Parameter vframe_77, Variable vh_82, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vh_82
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="height"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_77
}

predicate func_5(Variable vh_82, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(VariableAccess).getTarget()=vh_82
}

from Function func, Parameter vframe_77, Variable vh_82, Variable vplane_82, Variable vout_84, ArrayExpr target_2, ArrayExpr target_3, ExprStmt target_4, RelationalOperation target_5
where
not func_0(vh_82, target_4)
and not func_1(vh_82, target_5)
and func_2(vplane_82, vout_84, target_2)
and func_3(vframe_77, vplane_82, target_3)
and func_4(vframe_77, vh_82, target_4)
and func_5(vh_82, target_5)
and vframe_77.getType().hasName("AVFrame *")
and vh_82.getType().hasName("int")
and vplane_82.getType().hasName("int")
and vout_84.getType().hasName("AVFrame *")
and vframe_77.getParentScope+() = func
and vh_82.getParentScope+() = func
and vplane_82.getParentScope+() = func
and vout_84.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
