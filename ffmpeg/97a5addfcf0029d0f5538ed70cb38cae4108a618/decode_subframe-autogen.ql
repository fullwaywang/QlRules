/**
 * @name ffmpeg-97a5addfcf0029d0f5538ed70cb38cae4108a618-decode_subframe
 * @id cpp/ffmpeg/97a5addfcf0029d0f5538ed70cb38cae4108a618/decode-subframe
 * @description ffmpeg-97a5addfcf0029d0f5538ed70cb38cae4108a618-libavcodec/wmaprodec.c-decode_subframe CVE-2012-2789
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_1057, ArrayExpr target_3, ArrayExpr target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(BinaryBitwiseOperation).getValue()="8192"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1057
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="num_vec_coeffs %d is too large\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("int")
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="3199971767"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vnum_bits_1169, Parameter vs_1057, BinaryBitwiseOperation target_2) {
		target_2.getLeftOperand().(FunctionCall).getTarget().hasName("get_bits")
		and target_2.getLeftOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_2.getLeftOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1057
		and target_2.getLeftOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vnum_bits_1169
		and target_2.getRightOperand().(Literal).getValue()="2"
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="num_vec_coeffs"
		and target_2.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="channel"
		and target_2.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1057
		and target_2.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_3(Parameter vs_1057, ArrayExpr target_3) {
		target_3.getArrayBase().(PointerFieldAccess).getTarget().getName()="channel_indexes_for_cur_subframe"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1057
		and target_3.getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_4(Parameter vs_1057, ArrayExpr target_4) {
		target_4.getArrayBase().(PointerFieldAccess).getTarget().getName()="channel"
		and target_4.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1057
		and target_4.getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Variable vnum_bits_1169, Parameter vs_1057, BinaryBitwiseOperation target_2, ArrayExpr target_3, ArrayExpr target_4
where
not func_0(vs_1057, target_3, target_4)
and func_2(vnum_bits_1169, vs_1057, target_2)
and func_3(vs_1057, target_3)
and func_4(vs_1057, target_4)
and vnum_bits_1169.getType().hasName("int")
and vs_1057.getType().hasName("WMAProDecodeCtx *")
and vnum_bits_1169.(LocalVariable).getFunction() = func
and vs_1057.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
