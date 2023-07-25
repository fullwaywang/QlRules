/**
 * @name libwebp-907208f97ead639bd521cf355a2f203f462eade6-DecodeRemaining
 * @id cpp/libwebp/907208f97ead639bd521cf355a2f203f462eade6/DecodeRemaining
 * @description libwebp-907208f97ead639bd521cf355a2f203f462eade6-src/dec/idec_dec.c-DecodeRemaining CVE-2018-25013
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdec_448, Parameter videc_447, NotExpr target_1, LogicalAndExpr target_2, FunctionCall target_3, ExprStmt target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="mt_method_"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdec_448
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="Sync"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("WebPGetWorkerInterface")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(VariableCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="worker_"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("IDecError")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=videc_447
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vdec_448, NotExpr target_1) {
		target_1.getOperand().(FunctionCall).getTarget().hasName("VP8DecodeMB")
		and target_1.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdec_448
}

predicate func_2(Variable vdec_448, Parameter videc_447, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="num_parts_minus_one_"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdec_448
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("MemDataSize")
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="mem_"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=videc_447
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4096"
}

predicate func_3(Parameter videc_447, FunctionCall target_3) {
		target_3.getTarget().hasName("IDecError")
		and target_3.getArgument(0).(VariableAccess).getTarget()=videc_447
}

predicate func_4(Parameter videc_447, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="start_"
		and target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mem_"
		and target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=videc_447
		and target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="buf_"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(ValueFieldAccess).getTarget().getName()="buf_"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mem_"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=videc_447
}

from Function func, Variable vdec_448, Parameter videc_447, NotExpr target_1, LogicalAndExpr target_2, FunctionCall target_3, ExprStmt target_4
where
not func_0(vdec_448, videc_447, target_1, target_2, target_3, target_4)
and func_1(vdec_448, target_1)
and func_2(vdec_448, videc_447, target_2)
and func_3(videc_447, target_3)
and func_4(videc_447, target_4)
and vdec_448.getType().hasName("VP8Decoder *const")
and videc_447.getType().hasName("WebPIDecoder *const")
and vdec_448.getParentScope+() = func
and videc_447.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
