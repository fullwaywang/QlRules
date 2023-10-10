/**
 * @name ffmpeg-656cb0450aeb73b25d7d26980af342b37ac4c568-vp3_decode_frame
 * @id cpp/ffmpeg/656cb0450aeb73b25d7d26980af342b37ac4c568/vp3-decode-frame
 * @description ffmpeg-656cb0450aeb73b25d7d26980af342b37ac4c568-libavcodec/vp3.c-vp3_decode_frame CVE-2022-3109
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_2593, Variable vret_2595, NotExpr target_2, ExprStmt target_1, RelationalOperation target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="edge_emu_buffer"
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2593
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_2595
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-12"
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="error"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_2593, NotExpr target_2, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="edge_emu_buffer"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2593
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(Literal).getValue()="9"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(ConditionalExpr).getThen().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(ConditionalExpr).getThen().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Variable vs_2593, NotExpr target_2) {
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="edge_emu_buffer"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2593
}

predicate func_3(Variable vs_2593, Variable vret_2595, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_2595
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ff_thread_get_ext_buffer")
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="current_frame"
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_2593
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getValue()="1"
		and target_3.getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Variable vs_2593, Variable vret_2595, ExprStmt target_1, NotExpr target_2, RelationalOperation target_3
where
not func_0(vs_2593, vret_2595, target_2, target_1, target_3)
and func_1(vs_2593, target_2, target_1)
and func_2(vs_2593, target_2)
and func_3(vs_2593, vret_2595, target_3)
and vs_2593.getType().hasName("Vp3DecodeContext *")
and vret_2595.getType().hasName("int")
and vs_2593.getParentScope+() = func
and vret_2595.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
