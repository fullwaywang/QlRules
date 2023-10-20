/**
 * @name ffmpeg-695af8eed642ff0104834495652d1ee784a4c14d-field_end
 * @id cpp/ffmpeg/695af8eed642ff0104834495652d1ee784a4c14d/field-end
 * @description ffmpeg-695af8eed642ff0104834495652d1ee784a4c14d-libavcodec/h264.c-field_end CVE-2013-0869
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vh_2322, ExprStmt target_2, LogicalAndExpr target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="new"
		and target_0.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sps"
		and target_0.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_2322
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof FunctionCall
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_2324, Parameter vh_2322, LogicalAndExpr target_1) {
		target_1.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="picture_structure"
		and target_1.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2324
		and target_1.getAnOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="current_slice"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_2322
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_2(Parameter vh_2322, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="outputed_poc"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_2322
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="next_outputed_poc"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh_2322
}

from Function func, Variable vs_2324, Parameter vh_2322, LogicalAndExpr target_1, ExprStmt target_2
where
not func_0(vh_2322, target_2, target_1)
and func_1(vs_2324, vh_2322, target_1)
and func_2(vh_2322, target_2)
and vs_2324.getType().hasName("MpegEncContext *const")
and vh_2322.getType().hasName("H264Context *")
and vs_2324.(LocalVariable).getFunction() = func
and vh_2322.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
