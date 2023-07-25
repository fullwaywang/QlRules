/**
 * @name ffmpeg-a5d849b149ca67ced2d271dc84db0bc95a548abb-read_gab2_sub
 * @id cpp/ffmpeg/a5d849b149ca67ced2d271dc84db0bc95a548abb/read-gab2-sub
 * @description ffmpeg-a5d849b149ca67ced2d271dc84db0bc95a548abb-libavformat/avidec.c-read_gab2_sub CVE-2017-9993
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsub_demuxer_1071, LogicalAndExpr target_1, NotExpr target_2, NotExpr target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsub_demuxer_1071
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="srt"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsub_demuxer_1071
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="ass"
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(GotoStmt).getName() ="error"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(22)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(LogicalAndExpr target_1) {
		target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="7"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getValue()="2147483615"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="GAB2"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="l"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="5"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
}

predicate func_2(Variable vsub_demuxer_1071, NotExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vsub_demuxer_1071
}

predicate func_3(Variable vsub_demuxer_1071, NotExpr target_3) {
		target_3.getOperand().(FunctionCall).getTarget().hasName("avformat_open_input")
		and target_3.getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sub_ctx"
		and target_3.getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()=""
		and target_3.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsub_demuxer_1071
		and target_3.getOperand().(FunctionCall).getArgument(3).(Literal).getValue()="0"
}

from Function func, Variable vsub_demuxer_1071, LogicalAndExpr target_1, NotExpr target_2, NotExpr target_3
where
not func_0(vsub_demuxer_1071, target_1, target_2, target_3)
and func_1(target_1)
and func_2(vsub_demuxer_1071, target_2)
and func_3(vsub_demuxer_1071, target_3)
and vsub_demuxer_1071.getType().hasName("AVInputFormat *")
and vsub_demuxer_1071.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
