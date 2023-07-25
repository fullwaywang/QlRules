/**
 * @name ffmpeg-f18c873ab5ee3c78d00fdcc2582b39c133faecb4-adpcm_decode_frame
 * @id cpp/ffmpeg/f18c873ab5ee3c78d00fdcc2582b39c133faecb4/adpcm-decode-frame
 * @description ffmpeg-f18c873ab5ee3c78d00fdcc2582b39c133faecb4-libavcodec/adpcm.c-adpcm_decode_frame CVE-2013-0844
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vn_626, Variable vst_629, Variable vnb_samples_631, PostfixDecrExpr target_2, AddressOfExpr target_3, ExprStmt target_1, ExprStmt target_4) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_626
		and target_0.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vnb_samples_631
		and target_0.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_0.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(Literal).getValue()="1"
		and target_0.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vst_629
		and target_2.getOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_3.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vn_626, Variable vst_629, Variable vnb_samples_631, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_626
		and target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vnb_samples_631
		and target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(Literal).getValue()="1"
		and target_1.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vst_629
}

predicate func_2(Variable vn_626, PostfixDecrExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vn_626
}

predicate func_3(Variable vst_629, AddressOfExpr target_3) {
		target_3.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="status"
		and target_3.getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("ADPCMDecodeContext *")
		and target_3.getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vst_629
}

predicate func_4(Variable vn_626, Variable vst_629, Variable vnb_samples_631, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vn_626
		and target_4.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vnb_samples_631
		and target_4.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="2"
		and target_4.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(Literal).getValue()="1"
		and target_4.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vst_629
}

from Function func, Variable vn_626, Variable vst_629, Variable vnb_samples_631, ExprStmt target_1, PostfixDecrExpr target_2, AddressOfExpr target_3, ExprStmt target_4
where
not func_0(vn_626, vst_629, vnb_samples_631, target_2, target_3, target_1, target_4)
and func_1(vn_626, vst_629, vnb_samples_631, target_1)
and func_2(vn_626, target_2)
and func_3(vst_629, target_3)
and func_4(vn_626, vst_629, vnb_samples_631, target_4)
and vn_626.getType().hasName("int")
and vst_629.getType().hasName("int")
and vnb_samples_631.getType().hasName("int")
and vn_626.(LocalVariable).getFunction() = func
and vst_629.(LocalVariable).getFunction() = func
and vnb_samples_631.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
