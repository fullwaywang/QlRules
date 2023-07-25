/**
 * @name ffmpeg-3819db745da2ac7fb3faacb116788c32f4753f34-rpza_decode_stream
 * @id cpp/ffmpeg/3819db745da2ac7fb3faacb116788c32f4753f34/rpza-decode-stream
 * @description ffmpeg-3819db745da2ac7fb3faacb116788c32f4753f34-libavcodec/rpza.c-rpza_decode_stream CVE-2013-7009
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="4"
		and target_0.getParent() instanceof Initializer
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func) {
	exists(UnaryMinusExpr target_1 |
		target_1.getValue()="-4"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vstride_75, Parameter vs_72, Variable vwidth_74, Variable vrow_ptr_87, Variable vpixel_ptr_88, Variable vtotal_blocks_91, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vpixel_ptr_88
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="4"
		and target_2.getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vpixel_ptr_88
		and target_2.getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vwidth_74
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpixel_ptr_88
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vrow_ptr_87
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vstride_75
		and target_2.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(MulExpr).getRightOperand().(Literal).getValue()="4"
		and target_2.getStmt(2).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vtotal_blocks_91
		and target_2.getStmt(3).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtotal_blocks_91
		and target_2.getStmt(3).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_2.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_2.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_72
		and target_2.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_2.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="warning: block counter just went negative (this should not happen)\n"
}

predicate func_3(Variable vstride_75, Parameter vs_72, Variable vwidth_74, Variable vrow_ptr_87, Variable vpixel_ptr_88, Variable vtotal_blocks_91, BlockStmt target_3) {
		target_3.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vpixel_ptr_88
		and target_3.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="4"
		and target_3.getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vpixel_ptr_88
		and target_3.getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vwidth_74
		and target_3.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpixel_ptr_88
		and target_3.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vrow_ptr_87
		and target_3.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vstride_75
		and target_3.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(MulExpr).getRightOperand().(Literal).getValue()="4"
		and target_3.getStmt(2).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vtotal_blocks_91
		and target_3.getStmt(3).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtotal_blocks_91
		and target_3.getStmt(3).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_3.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_3.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_3.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_72
		and target_3.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_3.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="warning: block counter just went negative (this should not happen)\n"
}

predicate func_4(Variable vstride_75, Parameter vs_72, Variable vwidth_74, Variable vrow_ptr_87, Variable vpixel_ptr_88, Variable vtotal_blocks_91, BitwiseAndExpr target_8, BlockStmt target_4) {
		target_4.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vpixel_ptr_88
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(Literal).getValue()="4"
		and target_4.getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vpixel_ptr_88
		and target_4.getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vwidth_74
		and target_4.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpixel_ptr_88
		and target_4.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vrow_ptr_87
		and target_4.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vstride_75
		and target_4.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(MulExpr).getRightOperand().(Literal).getValue()="4"
		and target_4.getStmt(2).(ExprStmt).getExpr().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget()=vtotal_blocks_91
		and target_4.getStmt(3).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtotal_blocks_91
		and target_4.getStmt(3).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_4.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_4.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_4.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_72
		and target_4.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_4.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="warning: block counter just went negative (this should not happen)\n"
		and target_4.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_8
}

predicate func_7(BitwiseAndExpr target_8, Function func, EmptyStmt target_7) {
		target_7.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_8
		and target_7.getEnclosingFunction() = func
}

predicate func_8(BitwiseAndExpr target_8) {
		target_8.getLeftOperand().(VariableAccess).getTarget().getType().hasName("unsigned char")
		and target_8.getRightOperand().(HexLiteral).getValue()="224"
}

from Function func, Variable vstride_75, Parameter vs_72, Variable vwidth_74, Variable vrow_ptr_87, Variable vpixel_ptr_88, Variable vtotal_blocks_91, Literal target_0, BlockStmt target_2, BlockStmt target_3, BlockStmt target_4, EmptyStmt target_7, BitwiseAndExpr target_8
where
func_0(func, target_0)
and not func_1(func)
and func_2(vstride_75, vs_72, vwidth_74, vrow_ptr_87, vpixel_ptr_88, vtotal_blocks_91, target_2)
and func_3(vstride_75, vs_72, vwidth_74, vrow_ptr_87, vpixel_ptr_88, vtotal_blocks_91, target_3)
and func_4(vstride_75, vs_72, vwidth_74, vrow_ptr_87, vpixel_ptr_88, vtotal_blocks_91, target_8, target_4)
and func_7(target_8, func, target_7)
and func_8(target_8)
and vstride_75.getType().hasName("int")
and vs_72.getType().hasName("RpzaContext *")
and vwidth_74.getType().hasName("int")
and vrow_ptr_87.getType().hasName("int")
and vpixel_ptr_88.getType().hasName("int")
and vtotal_blocks_91.getType().hasName("int")
and vstride_75.(LocalVariable).getFunction() = func
and vs_72.getFunction() = func
and vwidth_74.(LocalVariable).getFunction() = func
and vrow_ptr_87.(LocalVariable).getFunction() = func
and vpixel_ptr_88.(LocalVariable).getFunction() = func
and vtotal_blocks_91.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
