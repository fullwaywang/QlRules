/**
 * @name ffmpeg-c77be3a35a0160d6af88056b0899f120f2eef38e-decode_mb
 * @id cpp/ffmpeg/c77be3a35a0160d6af88056b0899f120f2eef38e/decode-mb
 * @description ffmpeg-c77be3a35a0160d6af88056b0899f120f2eef38e-libavcodec/error_resilience.c-decode_mb CVE-2011-3941
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_43, ExprStmt target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("ff_init_block_index")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_43
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_43, LogicalAndExpr target_3, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("ff_update_block_index")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_43
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1)
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vs_43, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="dest"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_43
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="data"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="f"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="mb_y"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="uvlinesize"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_43
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="mb_x"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_43
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="16"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="chroma_x_shift"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_43
}

predicate func_3(Parameter vs_43, LogicalAndExpr target_3) {
		target_3.getAnOperand().(Literal).getValue()="1"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="codec_id"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_43
}

from Function func, Parameter vs_43, ExprStmt target_2, LogicalAndExpr target_3
where
not func_0(vs_43, target_2, func)
and not func_1(vs_43, target_3, func)
and func_2(vs_43, target_2)
and func_3(vs_43, target_3)
and vs_43.getType().hasName("MpegEncContext *")
and vs_43.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
