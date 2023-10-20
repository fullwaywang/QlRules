/**
 * @name ffmpeg-e0966eb140b3569b3d6b5b5008961944ef229c06-vp6_parse_coeff
 * @id cpp/ffmpeg/e0966eb140b3569b3d6b5b5008961944ef229c06/vp6-parse-coeff
 * @description ffmpeg-e0966eb140b3569b3d6b5b5008961944ef229c06-libavcodec/vp6.c-vp6_parse_coeff CVE-2011-4353
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcoeff_idx_430, ExprStmt target_3, LogicalOrExpr target_8) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcoeff_idx_430
		and target_0.getCondition().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcoeff_idx_430, Variable vcg_431, Variable vvp6_coeff_groups, ExprStmt target_9, ExprStmt target_11) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcg_431
		and target_1.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvp6_coeff_groups
		and target_1.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcoeff_idx_430
		and target_9.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_3(Variable vcoeff_idx_430, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcoeff_idx_430
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_4(Variable vcoeff_idx_430, Variable vrun_436, Variable vvp6_coeff_groups, AssignAddExpr target_4) {
		target_4.getLValue().(VariableAccess).getTarget()=vcoeff_idx_430
		and target_4.getRValue().(VariableAccess).getTarget()=vrun_436
		and target_4.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvp6_coeff_groups
}

predicate func_5(Variable vcoeff_idx_430, VariableAccess target_5) {
		target_5.getTarget()=vcoeff_idx_430
		and target_5.getParent().(LTExpr).getGreaterOperand().(Literal).getValue()="64"
}

predicate func_7(Variable vcoeff_idx_430, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getLesserOperand().(VariableAccess).getTarget()=vcoeff_idx_430
		and target_7.getGreaterOperand() instanceof Literal
}

predicate func_8(Variable vcoeff_idx_430, LogicalOrExpr target_8) {
		target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcoeff_idx_430
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getAnOperand().(FunctionCall).getTarget().hasName("vp56_rac_get_prob")
		and target_8.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("VP56RangeCoder *")
		and target_8.getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_8.getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_9(Variable vcoeff_idx_430, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_9.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="coeff_runv"
		and target_9.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("VP56Model *")
		and target_9.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcoeff_idx_430
		and target_9.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(RelationalOperation).getLesserOperand().(Literal).getValue()="6"
}

predicate func_11(Variable vcg_431, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_11.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_11.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="coeff_ract"
		and target_11.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_11.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_11.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcg_431
}

from Function func, Variable vcoeff_idx_430, Variable vcg_431, Variable vrun_436, Variable vvp6_coeff_groups, ExprStmt target_3, AssignAddExpr target_4, VariableAccess target_5, RelationalOperation target_7, LogicalOrExpr target_8, ExprStmt target_9, ExprStmt target_11
where
not func_0(vcoeff_idx_430, target_3, target_8)
and not func_1(vcoeff_idx_430, vcg_431, vvp6_coeff_groups, target_9, target_11)
and func_3(vcoeff_idx_430, target_3)
and func_4(vcoeff_idx_430, vrun_436, vvp6_coeff_groups, target_4)
and func_5(vcoeff_idx_430, target_5)
and func_7(vcoeff_idx_430, target_7)
and func_8(vcoeff_idx_430, target_8)
and func_9(vcoeff_idx_430, target_9)
and func_11(vcg_431, target_11)
and vcoeff_idx_430.getType().hasName("int")
and vcg_431.getType().hasName("int")
and vrun_436.getType().hasName("int")
and vvp6_coeff_groups.getType() instanceof ArrayType
and vcoeff_idx_430.(LocalVariable).getFunction() = func
and vcg_431.(LocalVariable).getFunction() = func
and vrun_436.(LocalVariable).getFunction() = func
and not vvp6_coeff_groups.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
