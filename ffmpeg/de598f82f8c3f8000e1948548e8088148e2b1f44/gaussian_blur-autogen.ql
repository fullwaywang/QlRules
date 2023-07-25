/**
 * @name ffmpeg-de598f82f8c3f8000e1948548e8088148e2b1f44-gaussian_blur
 * @id cpp/ffmpeg/de598f82f8c3f8000e1948548e8088148e2b1f44/gaussian-blur
 * @description ffmpeg-de598f82f8c3f8000e1948548e8088148e2b1f44-libavfilter/vf_edgedetect.c-gaussian_blur CVE-2020-22032
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vw_146, ExprStmt target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vw_146
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
		and target_0.getThen() instanceof ExprStmt
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vw_146) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vw_146
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2"
		and target_1.getThen() instanceof ExprStmt)
}

predicate func_2(Parameter vw_146, RelationalOperation target_7) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vw_146
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="3"
		and target_2.getThen() instanceof ExprStmt
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_7.getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vdst_147, Parameter vsrc_148, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdst_147
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrc_148
		and target_3.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
}

predicate func_4(Parameter vdst_147, Parameter vsrc_148, Variable vi_150, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdst_147
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_150
		and target_4.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrc_148
		and target_4.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_150
}

predicate func_5(Parameter vdst_147, Parameter vsrc_148, Variable vi_150, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdst_147
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_150
		and target_5.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_5.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrc_148
		and target_5.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_150
		and target_5.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_6(Parameter vw_146, Parameter vdst_147, Parameter vsrc_148, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdst_147
		and target_6.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsrc_148
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vw_146
}

predicate func_7(Parameter vw_146, Variable vi_150, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getLesserOperand().(VariableAccess).getTarget()=vi_150
		and target_7.getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vw_146
		and target_7.getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="2"
}

from Function func, Parameter vw_146, Parameter vdst_147, Parameter vsrc_148, Variable vi_150, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, RelationalOperation target_7
where
not func_0(vw_146, target_6)
and not func_1(vw_146)
and not func_2(vw_146, target_7)
and func_3(vdst_147, vsrc_148, target_3)
and func_4(vdst_147, vsrc_148, vi_150, target_4)
and func_5(vdst_147, vsrc_148, vi_150, target_5)
and func_6(vw_146, vdst_147, vsrc_148, target_6)
and func_7(vw_146, vi_150, target_7)
and vw_146.getType().hasName("int")
and vdst_147.getType().hasName("uint8_t *")
and vsrc_148.getType().hasName("const uint8_t *")
and vi_150.getType().hasName("int")
and vw_146.getParentScope+() = func
and vdst_147.getParentScope+() = func
and vsrc_148.getParentScope+() = func
and vi_150.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
