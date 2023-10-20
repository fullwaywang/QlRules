/**
 * @name ffmpeg-f67a0d115254461649470452058fa3c28c0df294-read_old_huffman_tables
 * @id cpp/ffmpeg/f67a0d115254461649470452058fa3c28c0df294/read-old-huffman-tables
 * @description ffmpeg-f67a0d115254461649470452058fa3c28c0df294-libavcodec/huffyuvdec.c-read_old_huffman_tables CVE-2013-0868
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue() instanceof FunctionCall
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(VariableAccess).getType().hasName("int")
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vi_207, Parameter vs_204, FunctionCall target_1) {
		target_1.getTarget().hasName("ff_init_vlc_sparse")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="vlc"
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_204
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_207
		and target_1.getArgument(1).(Literal).getValue()="11"
		and target_1.getArgument(2).(Literal).getValue()="256"
		and target_1.getArgument(3).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="len"
		and target_1.getArgument(3).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_204
		and target_1.getArgument(3).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_207
		and target_1.getArgument(4).(Literal).getValue()="1"
		and target_1.getArgument(5).(Literal).getValue()="1"
		and target_1.getArgument(6).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bits"
		and target_1.getArgument(6).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_204
		and target_1.getArgument(6).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_207
		and target_1.getArgument(7).(Literal).getValue()="4"
		and target_1.getArgument(8).(Literal).getValue()="4"
		and target_1.getArgument(9).(Literal).getValue()="0"
		and target_1.getArgument(10).(Literal).getValue()="0"
		and target_1.getArgument(11).(Literal).getValue()="0"
		and target_1.getArgument(12).(Literal).getValue()="0"
}

predicate func_2(Function func, ExprStmt target_2) {
		target_2.getExpr() instanceof FunctionCall
		and target_2.getEnclosingFunction() = func
}

from Function func, Variable vi_207, Parameter vs_204, FunctionCall target_1, ExprStmt target_2
where
not func_0(func)
and func_1(vi_207, vs_204, target_1)
and func_2(func, target_2)
and vi_207.getType().hasName("int")
and vs_204.getType().hasName("HYuvContext *")
and vi_207.(LocalVariable).getFunction() = func
and vs_204.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
