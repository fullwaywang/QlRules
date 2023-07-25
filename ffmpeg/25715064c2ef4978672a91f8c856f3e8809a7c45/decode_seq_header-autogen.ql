/**
 * @name ffmpeg-25715064c2ef4978672a91f8c856f3e8809a7c45-decode_seq_header
 * @id cpp/ffmpeg/25715064c2ef4978672a91f8c856f3e8809a7c45/decode-seq-header
 * @description ffmpeg-25715064c2ef4978672a91f8c856f3e8809a7c45-libavcodec/cavsdec.c-decode_seq_header CVE-2012-2777
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vs_610, ExprStmt target_8, AddressOfExpr target_9, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_bits")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_610
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="14"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_1)
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vs_610, AddressOfExpr target_10, ExprStmt target_8, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_610
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_610
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_610
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_610
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log_missing_feature")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_610
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Width/height changing in CAVS is"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_3)
		and target_10.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Variable vs_610, AddressOfExpr target_11, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_610
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_4)
		and target_11.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Variable vs_610) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(PointerFieldAccess).getTarget().getName()="height"
		and target_5.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_610
		and target_5.getRValue().(VariableAccess).getType().hasName("int"))
}

predicate func_6(Variable vs_610, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="width"
		and target_6.getQualifier().(VariableAccess).getTarget()=vs_610
		and target_6.getParent().(AssignExpr).getLValue() = target_6
		and target_6.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_bits")
		and target_6.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_6.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_610
		and target_6.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="14"
}

predicate func_7(Variable vs_610, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="height"
		and target_7.getQualifier().(VariableAccess).getTarget()=vs_610
		and target_7.getParent().(AssignExpr).getLValue() = target_7
		and target_7.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_bits")
		and target_7.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_7.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_610
		and target_7.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="14"
}

predicate func_8(Variable vs_610, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="height"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_610
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_bits")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_610
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="14"
}

predicate func_9(Variable vs_610, AddressOfExpr target_9) {
		target_9.getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_9.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_610
}

predicate func_10(Variable vs_610, AddressOfExpr target_10) {
		target_10.getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_10.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_610
}

predicate func_11(Variable vs_610, AddressOfExpr target_11) {
		target_11.getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_11.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_610
}

from Function func, Variable vs_610, PointerFieldAccess target_6, PointerFieldAccess target_7, ExprStmt target_8, AddressOfExpr target_9, AddressOfExpr target_10, AddressOfExpr target_11
where
not func_1(vs_610, target_8, target_9, func)
and not func_3(vs_610, target_10, target_8, func)
and not func_4(vs_610, target_11, func)
and not func_5(vs_610)
and func_6(vs_610, target_6)
and func_7(vs_610, target_7)
and func_8(vs_610, target_8)
and func_9(vs_610, target_9)
and func_10(vs_610, target_10)
and func_11(vs_610, target_11)
and vs_610.getType().hasName("MpegEncContext *")
and vs_610.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
