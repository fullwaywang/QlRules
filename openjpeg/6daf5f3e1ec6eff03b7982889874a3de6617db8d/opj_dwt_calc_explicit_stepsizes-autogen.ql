/**
 * @name openjpeg-6daf5f3e1ec6eff03b7982889874a3de6617db8d-opj_dwt_calc_explicit_stepsizes
 * @id cpp/openjpeg/6daf5f3e1ec6eff03b7982889874a3de6617db8d/opj-dwt-calc-explicit-stepsizes
 * @description openjpeg-6daf5f3e1ec6eff03b7982889874a3de6617db8d-src/lib/openjp2/dwt.c-opj_dwt_calc_explicit_stepsizes CVE-2020-27824
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlevel_1969, Variable vorient_1969, ExprStmt target_4, ExprStmt target_5) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("opj_dwt_getnorm_real")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vlevel_1969
		and target_0.getArgument(1).(VariableAccess).getTarget()=vorient_1969
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vorient_1969, Variable vopj_dwt_norms_real, VariableAccess target_1) {
		target_1.getTarget()=vorient_1969
		and target_1.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vopj_dwt_norms_real
}

predicate func_2(Variable vlevel_1969, VariableAccess target_2) {
		target_2.getTarget()=vlevel_1969
		and target_2.getParent().(ArrayExpr).getArrayBase() instanceof ArrayExpr
}

predicate func_3(Variable vlevel_1969, Variable vorient_1969, Variable vopj_dwt_norms_real, ArrayExpr target_3) {
		target_3.getArrayBase().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vopj_dwt_norms_real
		and target_3.getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vorient_1969
		and target_3.getArrayOffset().(VariableAccess).getTarget()=vlevel_1969
}

predicate func_4(Variable vlevel_1969, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlevel_1969
		and target_4.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="numresolutions"
		and target_4.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_5(Variable vorient_1969, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="qmfbid"
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vorient_1969
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(ConditionalExpr).getElse().(Literal).getValue()="2"
}

from Function func, Variable vlevel_1969, Variable vorient_1969, Variable vopj_dwt_norms_real, VariableAccess target_1, VariableAccess target_2, ArrayExpr target_3, ExprStmt target_4, ExprStmt target_5
where
not func_0(vlevel_1969, vorient_1969, target_4, target_5)
and func_1(vorient_1969, vopj_dwt_norms_real, target_1)
and func_2(vlevel_1969, target_2)
and func_3(vlevel_1969, vorient_1969, vopj_dwt_norms_real, target_3)
and func_4(vlevel_1969, target_4)
and func_5(vorient_1969, target_5)
and vlevel_1969.getType().hasName("OPJ_UINT32")
and vorient_1969.getType().hasName("OPJ_UINT32")
and vopj_dwt_norms_real.getType() instanceof ArrayType
and vlevel_1969.getParentScope+() = func
and vorient_1969.getParentScope+() = func
and not vopj_dwt_norms_real.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
