/**
 * @name ffmpeg-0846719dd11ab3f7a7caee13e7af71f71d913389-ff_ivi_decode_blocks
 * @id cpp/ffmpeg/0846719dd11ab3f7a7caee13e7af71f71d913389/ff-ivi-decode-blocks
 * @description ffmpeg-0846719dd11ab3f7a7caee13e7af71f71d913389-libavcodec/ivi_common.c-ff_ivi_decode_blocks CVE-2012-2791
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vband_333, BitwiseAndExpr target_1, LogicalAndExpr target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="transform_size"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vband_333
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="blk_size"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vband_333
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Too large transform\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="3199971767"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(6)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(BitwiseAndExpr target_1) {
		target_1.getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_1.getRightOperand().(Literal).getValue()="1"
}

predicate func_2(Parameter vband_333, LogicalAndExpr target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="is_2d_trans"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vband_333
}

predicate func_3(Parameter vband_333, ExprStmt target_3) {
		target_3.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="inv_transform"
		and target_3.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vband_333
		and target_3.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("int32_t[64]")
		and target_3.getExpr().(VariableCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="buf"
		and target_3.getExpr().(VariableCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vband_333
		and target_3.getExpr().(VariableCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_3.getExpr().(VariableCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="pitch"
		and target_3.getExpr().(VariableCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vband_333
		and target_3.getExpr().(VariableCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("uint8_t[8]")
}

from Function func, Parameter vband_333, BitwiseAndExpr target_1, LogicalAndExpr target_2, ExprStmt target_3
where
not func_0(vband_333, target_1, target_2, target_3)
and func_1(target_1)
and func_2(vband_333, target_2)
and func_3(vband_333, target_3)
and vband_333.getType().hasName("IVIBandDesc *")
and vband_333.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
