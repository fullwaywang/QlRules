/**
 * @name ffmpeg-c6939f65a116b1ffed345d29d8621ee4ffb32235-config_props_output
 * @id cpp/ffmpeg/c6939f65a116b1ffed345d29d8621ee4ffb32235/config-props-output
 * @description ffmpeg-c6939f65a116b1ffed345d29d8621ee4ffb32235-libavfilter/vf_transpose.c-config_props_output CVE-2018-6392
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_194, Variable vdesc_in_197, ExprStmt target_2, ExprStmt target_3, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="planes"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_194
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="nb_components"
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdesc_in_197
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0)
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vdesc_out_196, Variable vdesc_in_197, ExprStmt target_3, Function func) {
	exists(DoStmt target_1 |
		target_1.getCondition() instanceof Literal
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nb_components"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdesc_in_197
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nb_components"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdesc_out_196
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Assertion %s failed at %s:%d\n"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="desc_in->nb_components == desc_out->nb_components"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("abort")
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_1)
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_2(Variable vs_194, Variable vdesc_in_197, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="vsub"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_194
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="log2_chroma_h"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdesc_in_197
}

predicate func_3(Variable vs_194, Variable vdesc_out_196, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("av_image_fill_max_pixsteps")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pixsteps"
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_194
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdesc_out_196
}

from Function func, Variable vs_194, Variable vdesc_out_196, Variable vdesc_in_197, ExprStmt target_2, ExprStmt target_3
where
not func_0(vs_194, vdesc_in_197, target_2, target_3, func)
and not func_1(vdesc_out_196, vdesc_in_197, target_3, func)
and func_2(vs_194, vdesc_in_197, target_2)
and func_3(vs_194, vdesc_out_196, target_3)
and vs_194.getType().hasName("TransContext *")
and vdesc_out_196.getType().hasName("const AVPixFmtDescriptor *")
and vdesc_in_197.getType().hasName("const AVPixFmtDescriptor *")
and vs_194.getParentScope+() = func
and vdesc_out_196.getParentScope+() = func
and vdesc_in_197.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
