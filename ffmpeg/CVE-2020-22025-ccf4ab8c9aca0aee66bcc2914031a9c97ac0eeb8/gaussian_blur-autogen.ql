/**
 * @name ffmpeg-ccf4ab8c9aca0aee66bcc2914031a9c97ac0eeb8-gaussian_blur
 * @id cpp/ffmpeg/ccf4ab8c9aca0aee66bcc2914031a9c97ac0eeb8/gaussian-blur
 * @description ffmpeg-ccf4ab8c9aca0aee66bcc2914031a9c97ac0eeb8-libavfilter/vf_edgedetect.c-gaussian_blur CVE-2020-22025
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vh_146, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vh_146
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
		and target_0.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vh_146, RelationalOperation target_6, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vh_146
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2"
		and target_1.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_1)
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vh_146, RelationalOperation target_6, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vh_146
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="3"
		and target_2.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_2)
		and target_6.getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vw_146, Parameter vdst_147, Parameter vsrc_148, Function func, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdst_147
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsrc_148
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vw_146
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Parameter vw_146, Parameter vdst_147, Parameter vsrc_148, Function func, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdst_147
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsrc_148
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vw_146
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Parameter vw_146, Parameter vdst_147, Parameter vsrc_148, Function func, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdst_147
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vsrc_148
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vw_146
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Parameter vh_146, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vh_146
		and target_6.getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="2"
}

from Function func, Parameter vw_146, Parameter vh_146, Parameter vdst_147, Parameter vsrc_148, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, RelationalOperation target_6
where
not func_0(vh_146, func)
and not func_1(vh_146, target_6, func)
and not func_2(vh_146, target_6, func)
and func_3(vw_146, vdst_147, vsrc_148, func, target_3)
and func_4(vw_146, vdst_147, vsrc_148, func, target_4)
and func_5(vw_146, vdst_147, vsrc_148, func, target_5)
and func_6(vh_146, target_6)
and vw_146.getType().hasName("int")
and vh_146.getType().hasName("int")
and vdst_147.getType().hasName("uint8_t *")
and vsrc_148.getType().hasName("const uint8_t *")
and vw_146.getParentScope+() = func
and vh_146.getParentScope+() = func
and vdst_147.getParentScope+() = func
and vsrc_148.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
