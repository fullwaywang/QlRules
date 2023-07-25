/**
 * @name vim-4875d6ab068f09df88d24d81de40dcd8d56e243d-generate_loadvar
 * @id cpp/vim/4875d6ab068f09df88d24d81de40dcd8d56e243d/generate-loadvar
 * @description vim-4875d6ab068f09df88d24d81de40dcd8d56e243d-src/vim9compile.c-generate_loadvar CVE-2022-2874
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcctx_1121, VariableAccess target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ctx_skip"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcctx_1121
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_2
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vlvar_1124, Parameter vtype_1125, Parameter vcctx_1121, VariableAccess target_2, IfStmt target_1) {
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="lv_from_outer"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlvar_1124
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("generate_LOADOUTER")
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcctx_1121
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="lv_idx"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlvar_1124
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="lv_from_outer"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlvar_1124
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtype_1125
		and target_1.getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("generate_LOAD")
		and target_1.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcctx_1121
		and target_1.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="lv_idx"
		and target_1.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlvar_1124
		and target_1.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_1.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vtype_1125
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_2
}

predicate func_2(Parameter vdest_1122, VariableAccess target_2) {
		target_2.getTarget()=vdest_1122
}

predicate func_3(Parameter vcctx_1121, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("generate_LOADV")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcctx_1121
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
}

predicate func_4(Parameter vlvar_1124, Parameter vtype_1125, Parameter vcctx_1121, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("generate_LOADOUTER")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcctx_1121
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="lv_idx"
		and target_4.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlvar_1124
		and target_4.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="lv_from_outer"
		and target_4.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlvar_1124
		and target_4.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vtype_1125
}

from Function func, Parameter vdest_1122, Parameter vlvar_1124, Parameter vtype_1125, Parameter vcctx_1121, IfStmt target_1, VariableAccess target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vcctx_1121, target_2, target_3, target_4)
and func_1(vlvar_1124, vtype_1125, vcctx_1121, target_2, target_1)
and func_2(vdest_1122, target_2)
and func_3(vcctx_1121, target_3)
and func_4(vlvar_1124, vtype_1125, vcctx_1121, target_4)
and vdest_1122.getType().hasName("assign_dest_T")
and vlvar_1124.getType().hasName("lvar_T *")
and vtype_1125.getType().hasName("type_T *")
and vcctx_1121.getType().hasName("cctx_T *")
and vdest_1122.getParentScope+() = func
and vlvar_1124.getParentScope+() = func
and vtype_1125.getParentScope+() = func
and vcctx_1121.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
