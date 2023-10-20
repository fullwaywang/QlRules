/**
 * @name ffmpeg-9807d3976be0e92e4ece3b4b1701be894cd7c2e1-read_part_of_packet
 * @id cpp/ffmpeg/9807d3976be0e92e4ece3b4b1701be894cd7c2e1/read-part-of-packet
 * @description ffmpeg-9807d3976be0e92e4ece3b4b1701be894cd7c2e1-libavformat/pva.c-read_part_of_packet CVE-2018-1999012
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpb_84, NotExpr target_1, ExprStmt target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("avio_feof")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpb_84
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-541478725"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(7)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(NotExpr target_1) {
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="continue_pes"
}

predicate func_2(Variable vpb_84, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("avio_r8")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpb_84
}

predicate func_3(Variable vpb_84, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("avio_skip")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpb_84
		and target_3.getExpr().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(Literal).getValue()="9"
}

from Function func, Variable vpb_84, NotExpr target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vpb_84, target_1, target_2, target_3)
and func_1(target_1)
and func_2(vpb_84, target_2)
and func_3(vpb_84, target_3)
and vpb_84.getType().hasName("AVIOContext *")
and vpb_84.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
