/**
 * @name ffmpeg-bb4b0ad83b13c3af57675e80163f3f333adef96f-vp5_parse_coeff
 * @id cpp/ffmpeg/bb4b0ad83b13c3af57675e80163f3f333adef96f/vp5-parse-coeff
 * @description ffmpeg-bb4b0ad83b13c3af57675e80163f3f333adef96f-libavcodec/vp5.c-vp5_parse_coeff CVE-2011-4353
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcoeff_idx_174, ExprStmt target_10) {
	exists(PostfixIncrExpr target_0 |
		target_0.getOperand().(VariableAccess).getTarget()=vcoeff_idx_174
		and target_0.getOperand().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcoeff_idx_174, ExprStmt target_4, ExprStmt target_11) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcoeff_idx_174
		and target_1.getCondition().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_2(Variable vcoeff_idx_174, Variable vcg_175, Variable vvp5_coeff_groups, ExprStmt target_12, ExprStmt target_14) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcg_175
		and target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvp5_coeff_groups
		and target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcoeff_idx_174
		and target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_14.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_4(Variable vcoeff_idx_174, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcoeff_idx_174
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_5(Variable vcoeff_idx_174, VariableAccess target_5) {
		target_5.getTarget()=vcoeff_idx_174
		and target_5.getParent().(LTExpr).getGreaterOperand().(Literal).getValue()="64"
}

predicate func_7(Variable vcoeff_idx_174, VariableAccess target_7) {
		target_7.getTarget()=vcoeff_idx_174
}

predicate func_8(Variable vcoeff_idx_174, RelationalOperation target_8) {
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getLesserOperand().(VariableAccess).getTarget()=vcoeff_idx_174
		and target_8.getGreaterOperand() instanceof Literal
}

predicate func_9(Variable vcoeff_idx_174, Variable vvp5_coeff_groups, PrefixIncrExpr target_9) {
		target_9.getOperand().(VariableAccess).getTarget()=vcoeff_idx_174
		and target_9.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvp5_coeff_groups
}

predicate func_10(Variable vcoeff_idx_174, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_10.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="coeff_ctx"
		and target_10.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("VP56Context *")
		and target_10.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_10.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_10.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcoeff_idx_174
}

predicate func_11(Variable vcoeff_idx_174, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="coeff_ctx"
		and target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("VP56Context *")
		and target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_11.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcoeff_idx_174
		and target_11.getExpr().(AssignExpr).getRValue().(Literal).getValue()="4"
}

predicate func_12(Variable vcoeff_idx_174, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="coeff_ctx"
		and target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("VP56Context *")
		and target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType() instanceof ArrayType
		and target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_12.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcoeff_idx_174
		and target_12.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_14(Variable vcg_175, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint8_t *")
		and target_14.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="coeff_ract"
		and target_14.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("VP56Model *")
		and target_14.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_14.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_14.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcg_175
}

from Function func, Variable vcoeff_idx_174, Variable vcg_175, Variable vvp5_coeff_groups, ExprStmt target_4, VariableAccess target_5, VariableAccess target_7, RelationalOperation target_8, PrefixIncrExpr target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_14
where
not func_0(vcoeff_idx_174, target_10)
and not func_1(vcoeff_idx_174, target_4, target_11)
and not func_2(vcoeff_idx_174, vcg_175, vvp5_coeff_groups, target_12, target_14)
and func_4(vcoeff_idx_174, target_4)
and func_5(vcoeff_idx_174, target_5)
and func_7(vcoeff_idx_174, target_7)
and func_8(vcoeff_idx_174, target_8)
and func_9(vcoeff_idx_174, vvp5_coeff_groups, target_9)
and func_10(vcoeff_idx_174, target_10)
and func_11(vcoeff_idx_174, target_11)
and func_12(vcoeff_idx_174, target_12)
and func_14(vcg_175, target_14)
and vcoeff_idx_174.getType().hasName("int")
and vcg_175.getType().hasName("int")
and vvp5_coeff_groups.getType() instanceof ArrayType
and vcoeff_idx_174.(LocalVariable).getFunction() = func
and vcg_175.(LocalVariable).getFunction() = func
and not vvp5_coeff_groups.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
