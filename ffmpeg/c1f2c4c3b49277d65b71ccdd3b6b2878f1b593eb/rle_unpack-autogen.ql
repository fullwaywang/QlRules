/**
 * @name ffmpeg-c1f2c4c3b49277d65b71ccdd3b6b2878f1b593eb-rle_unpack
 * @id cpp/ffmpeg/c1f2c4c3b49277d65b71ccdd3b6b2878f1b593eb/rle-unpack
 * @description ffmpeg-c1f2c4c3b49277d65b71ccdd3b6b2878f1b593eb-libavcodec/vmdav.c-rle_unpack CVE-2013-3670
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_154, VariableAccess target_0) {
		target_0.getTarget()=vi_154
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_1(Variable vi_154, BlockStmt target_14, VariableAccess target_1) {
		target_1.getTarget()=vi_154
		and target_1.getParent().(LTExpr).getGreaterOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_14
}

predicate func_2(Variable vi_154, VariableAccess target_2) {
		target_2.getTarget()=vi_154
}

predicate func_3(Variable vi_154, VariableAccess target_3) {
		target_3.getTarget()=vi_154
}

predicate func_5(Function func) {
	exists(MulExpr target_5 |
		target_5.getLeftOperand() instanceof Literal
		and target_5.getRightOperand().(VariableAccess).getType().hasName("int")
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("int[2]")
		and target_6.getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_6.getRValue() instanceof FunctionCall
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(BitwiseAndExpr target_15, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("int[2]")
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_7.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(3)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(ArrayExpr target_8 |
		target_8.getArrayBase().(VariableAccess).getType().hasName("int[2]")
		and target_8.getArrayOffset().(Literal).getValue()="0"
		and target_8.getParent().(AssignExpr).getRValue() = target_8
		and target_8.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(ArrayExpr target_9 |
		target_9.getArrayBase().(VariableAccess).getType().hasName("int[2]")
		and target_9.getArrayOffset().(Literal).getValue()="1"
		and target_9.getParent().(AssignExpr).getRValue() = target_9
		and target_9.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Variable vgb_156, FunctionCall target_10) {
		target_10.getTarget().hasName("bytestream2_get_byteu")
		and target_10.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgb_156
		and target_10.getParent().(AssignExpr).getRValue() = target_10
		and target_10.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("unsigned char *")
}

predicate func_11(Variable vgb_156, FunctionCall target_11) {
		target_11.getTarget().hasName("bytestream2_get_byteu")
		and target_11.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgb_156
		and target_11.getParent().(AssignExpr).getRValue() = target_11
		and target_11.getParent().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("unsigned char *")
}

predicate func_13(Variable vgb_156, FunctionCall target_13) {
		target_13.getTarget().hasName("bytestream2_skip")
		and target_13.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vgb_156
		and target_13.getArgument(1) instanceof Literal
}

predicate func_14(BlockStmt target_14) {
		target_14.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_14.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_14.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_14.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_15(BitwiseAndExpr target_15) {
		target_15.getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_15.getRightOperand().(HexLiteral).getValue()="128"
}

from Function func, Variable vi_154, Variable vgb_156, VariableAccess target_0, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, FunctionCall target_10, FunctionCall target_11, FunctionCall target_13, BlockStmt target_14, BitwiseAndExpr target_15
where
func_0(vi_154, target_0)
and func_1(vi_154, target_14, target_1)
and func_2(vi_154, target_2)
and func_3(vi_154, target_3)
and not func_5(func)
and not func_6(func)
and not func_7(target_15, func)
and not func_8(func)
and not func_9(func)
and func_10(vgb_156, target_10)
and func_11(vgb_156, target_11)
and func_13(vgb_156, target_13)
and func_14(target_14)
and func_15(target_15)
and vi_154.getType().hasName("int")
and vgb_156.getType().hasName("GetByteContext")
and vi_154.(LocalVariable).getFunction() = func
and vgb_156.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
