/**
 * @name ffmpeg-36aad4f1cc707feb15f071260a99f239b6623a59-iff_read_header
 * @id cpp/ffmpeg/36aad4f1cc707feb15f071260a99f239b6623a59/iff-read-header
 * @description ffmpeg-36aad4f1cc707feb15f071260a99f239b6623a59-libavformat/iff.c-iff_read_header CVE-2013-2495
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_110, Variable vdata_size_116, VariableAccess target_1, ExprStmt target_2, RelationalOperation target_3, RelationalOperation target_4, ExprStmt target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vdata_size_116
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="3"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdata_size_116
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="768"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RemExpr).getLeftOperand().(VariableAccess).getTarget()=vdata_size_116
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RemExpr).getRightOperand().(Literal).getValue()="3"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_110
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalid CMAP chunk size %d\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vdata_size_116
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="3199971767"
		and target_0.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_1
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vchunk_id_116, VariableAccess target_1) {
		target_1.getTarget()=vchunk_id_116
}

predicate func_2(Parameter vs_110, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("AVStream *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("avformat_new_stream")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_110
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_3(Parameter vs_110, Variable vdata_size_116, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_metadata")
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_110
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdata_size_116
		and target_3.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_4(Variable vdata_size_116, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vdata_size_116
		and target_4.getGreaterOperand().(Literal).getValue()="4"
}

predicate func_5(Variable vdata_size_116, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="extradata_size"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="codec"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("AVStream *")
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vdata_size_116
}

from Function func, Parameter vs_110, Variable vchunk_id_116, Variable vdata_size_116, VariableAccess target_1, ExprStmt target_2, RelationalOperation target_3, RelationalOperation target_4, ExprStmt target_5
where
not func_0(vs_110, vdata_size_116, target_1, target_2, target_3, target_4, target_5)
and func_1(vchunk_id_116, target_1)
and func_2(vs_110, target_2)
and func_3(vs_110, vdata_size_116, target_3)
and func_4(vdata_size_116, target_4)
and func_5(vdata_size_116, target_5)
and vs_110.getType().hasName("AVFormatContext *")
and vchunk_id_116.getType().hasName("uint32_t")
and vdata_size_116.getType().hasName("uint32_t")
and vs_110.getFunction() = func
and vchunk_id_116.(LocalVariable).getFunction() = func
and vdata_size_116.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
