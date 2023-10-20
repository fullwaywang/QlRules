/**
 * @name ffmpeg-4f1279154ee9baf2078241bf5619774970d18b25-read_header
 * @id cpp/ffmpeg/4f1279154ee9baf2078241bf5619774970d18b25/read-header
 * @description ffmpeg-4f1279154ee9baf2078241bf5619774970d18b25-libavcodec/shorten.c-read_header CVE-2013-0873
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_327, LogicalOrExpr target_1, ExprStmt target_2, ExprStmt target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="channels"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_327
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_327, LogicalOrExpr target_1) {
		target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="channels"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_327
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="channels"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_327
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="8"
}

predicate func_2(Parameter vs_327, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_327
		and target_2.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="too many channels: %d\n"
		and target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="channels"
		and target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_327
}

predicate func_3(Parameter vs_327, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="channels"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_327
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="channels"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_327
}

from Function func, Parameter vs_327, LogicalOrExpr target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vs_327, target_1, target_2, target_3)
and func_1(vs_327, target_1)
and func_2(vs_327, target_2)
and func_3(vs_327, target_3)
and vs_327.getType().hasName("ShortenContext *")
and vs_327.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
