/**
 * @name ffmpeg-e8714f6f93d1a32f4e4655209960afcf4c185214-ff_h264_free_tables
 * @id cpp/ffmpeg/e8714f6f93d1a32f4e4655209960afcf4c185214/ff-h264-free-tables
 * @description ffmpeg-e8714f6f93d1a32f4e4655209960afcf4c185214-libavcodec/h264.c-ff_h264_free_tables CVE-2015-3417
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vh_367, LogicalAndExpr target_1, AddressOfExpr target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="delayed_pic"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_367
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="144"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vh_367, LogicalAndExpr target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="DPB"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_367
}

predicate func_2(Parameter vh_367, AddressOfExpr target_2) {
		target_2.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="DPB"
		and target_2.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_367
		and target_2.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Parameter vh_367, LogicalAndExpr target_1, AddressOfExpr target_2
where
not func_0(vh_367, target_1, target_2)
and func_1(vh_367, target_1)
and func_2(vh_367, target_2)
and vh_367.getType().hasName("H264Context *")
and vh_367.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
