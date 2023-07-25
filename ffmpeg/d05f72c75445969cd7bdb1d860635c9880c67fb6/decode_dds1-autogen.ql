/**
 * @name ffmpeg-d05f72c75445969cd7bdb1d860635c9880c67fb6-decode_dds1
 * @id cpp/ffmpeg/d05f72c75445969cd7bdb1d860635c9880c67fb6/decode-dds1
 * @description ffmpeg-d05f72c75445969cd7bdb1d860635c9880c67fb6-libavcodec/dfa.c-decode_dds1 CVE-2012-2798
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="2"
		and not target_0.getValue()="3"
		and target_0.getParent().(AddExpr).getParent().(LTExpr).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="2"
		and not target_1.getValue()="73"
		and target_1.getParent().(LTExpr).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand() instanceof PointerArithmeticOperation
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vv_146, ExprStmt target_12) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vv_146
		and target_2.getRValue() instanceof MulExpr
		and target_12.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_2.getLValue().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vframe_141, Variable vframe_end_144, ReturnStmt target_13, PointerArithmeticOperation target_14) {
	exists(PointerArithmeticOperation target_3 |
		target_3.getLeftOperand().(VariableAccess).getTarget()=vframe_141
		and target_3.getRightOperand().(VariableAccess).getTarget()=vframe_end_144
		and target_3.getParent().(LTExpr).getLesserOperand() instanceof PointerArithmeticOperation
		and target_3.getParent().(LTExpr).getGreaterOperand() instanceof Literal
		and target_3.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_13
		and target_14.getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vframe_141, Variable vv_146, BitwiseAndExpr target_17, ExprStmt target_18, RelationalOperation target_19) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vframe_141
		and target_6.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vv_146
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_18.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_19.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_8(Parameter vframe_141, Variable vframe_end_144, ReturnStmt target_13, PointerArithmeticOperation target_8) {
		target_8.getLeftOperand().(VariableAccess).getTarget()=vframe_end_144
		and target_8.getRightOperand().(VariableAccess).getTarget()=vframe_141
		and target_8.getParent().(LTExpr).getGreaterOperand() instanceof Literal
		and target_8.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_13
}

predicate func_9(Function func, UnaryMinusExpr target_9) {
		target_9.getValue()="3199971767"
		and target_9.getEnclosingFunction() = func
}

predicate func_10(Variable vmask_145, Variable vbitbuf_145, BlockStmt target_20, BitwiseAndExpr target_10) {
		target_10.getLeftOperand().(VariableAccess).getTarget()=vbitbuf_145
		and target_10.getRightOperand().(VariableAccess).getTarget()=vmask_145
		and target_10.getParent().(IfStmt).getThen()=target_20
}

predicate func_11(Parameter vgb_141, MulExpr target_11) {
		target_11.getLeftOperand().(FunctionCall).getTarget().hasName("bytestream2_get_le16")
		and target_11.getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgb_141
		and target_11.getRightOperand().(Literal).getValue()="2"
}

predicate func_12(Variable vv_146, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_12.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vv_146
		and target_12.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="13"
		and target_12.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_12.getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
}

predicate func_13(ReturnStmt target_13) {
		target_13.getExpr() instanceof UnaryMinusExpr
}

predicate func_14(Parameter vframe_141, PointerArithmeticOperation target_14) {
		target_14.getAnOperand().(VariableAccess).getTarget()=vframe_141
		and target_14.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_14.getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_17(Variable vmask_145, Variable vbitbuf_145, BitwiseAndExpr target_17) {
		target_17.getLeftOperand().(VariableAccess).getTarget()=vbitbuf_145
		and target_17.getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vmask_145
		and target_17.getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
}

predicate func_18(Parameter vframe_141, ExprStmt target_18) {
		target_18.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vframe_141
		and target_18.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_19(Parameter vframe_141, Variable vframe_end_144, RelationalOperation target_19) {
		 (target_19 instanceof GTExpr or target_19 instanceof LTExpr)
		and target_19.getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vframe_end_144
		and target_19.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vframe_141
		and target_19.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_19.getGreaterOperand().(AddExpr).getAnOperand() instanceof Literal
}

predicate func_20(Parameter vgb_141, Variable vv_146, BlockStmt target_20) {
		target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vv_146
		and target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("bytestream2_get_le16")
		and target_20.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vgb_141
		and target_20.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_20.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vv_146
		and target_20.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="8191"
		and target_20.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
}

from Function func, Parameter vgb_141, Parameter vframe_141, Variable vframe_end_144, Variable vmask_145, Variable vbitbuf_145, Variable vv_146, Literal target_0, Literal target_1, PointerArithmeticOperation target_8, UnaryMinusExpr target_9, BitwiseAndExpr target_10, MulExpr target_11, ExprStmt target_12, ReturnStmt target_13, PointerArithmeticOperation target_14, BitwiseAndExpr target_17, ExprStmt target_18, RelationalOperation target_19, BlockStmt target_20
where
func_0(func, target_0)
and func_1(func, target_1)
and not func_2(vv_146, target_12)
and not func_3(vframe_141, vframe_end_144, target_13, target_14)
and not func_6(vframe_141, vv_146, target_17, target_18, target_19)
and func_8(vframe_141, vframe_end_144, target_13, target_8)
and func_9(func, target_9)
and func_10(vmask_145, vbitbuf_145, target_20, target_10)
and func_11(vgb_141, target_11)
and func_12(vv_146, target_12)
and func_13(target_13)
and func_14(vframe_141, target_14)
and func_17(vmask_145, vbitbuf_145, target_17)
and func_18(vframe_141, target_18)
and func_19(vframe_141, vframe_end_144, target_19)
and func_20(vgb_141, vv_146, target_20)
and vgb_141.getType().hasName("GetByteContext *")
and vframe_141.getType().hasName("uint8_t *")
and vframe_end_144.getType().hasName("const uint8_t *")
and vmask_145.getType().hasName("int")
and vbitbuf_145.getType().hasName("int")
and vv_146.getType().hasName("int")
and vgb_141.getFunction() = func
and vframe_141.getFunction() = func
and vframe_end_144.(LocalVariable).getFunction() = func
and vmask_145.(LocalVariable).getFunction() = func
and vbitbuf_145.(LocalVariable).getFunction() = func
and vv_146.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
