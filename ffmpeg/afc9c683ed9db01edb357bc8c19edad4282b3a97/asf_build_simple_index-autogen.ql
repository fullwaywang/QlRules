/**
 * @name ffmpeg-afc9c683ed9db01edb357bc8c19edad4282b3a97-asf_build_simple_index
 * @id cpp/ffmpeg/afc9c683ed9db01edb357bc8c19edad4282b3a97/asf-build-simple-index
 * @description ffmpeg-afc9c683ed9db01edb357bc8c19edad4282b3a97-libavformat/asfdec_f.c-asf_build_simple_index CVE-2017-14223
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_1568, Variable vret_1573, AddExpr target_1, ExprStmt target_2, RelationalOperation target_3, ReturnStmt target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("avio_feof")
		and target_0.getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pb"
		and target_0.getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1568
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_1573
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1094995529"
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="end"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getExpr().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_1568, AddExpr target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="data_offset"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="internal"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1568
		and target_1.getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="packet_size"
		and target_1.getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1568
}

predicate func_2(Parameter vs_1568, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_1568
		and target_2.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="48"
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="pktnum:%d, pktct:%d  pts: %ld\n"
}

predicate func_3(Parameter vs_1568, Variable vret_1573, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_1573
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ff_get_guid")
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pb"
		and target_3.getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1568
		and target_3.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_4(Variable vret_1573, ReturnStmt target_4) {
		target_4.getExpr().(VariableAccess).getTarget()=vret_1573
}

from Function func, Parameter vs_1568, Variable vret_1573, AddExpr target_1, ExprStmt target_2, RelationalOperation target_3, ReturnStmt target_4
where
not func_0(vs_1568, vret_1573, target_1, target_2, target_3, target_4)
and func_1(vs_1568, target_1)
and func_2(vs_1568, target_2)
and func_3(vs_1568, vret_1573, target_3)
and func_4(vret_1573, target_4)
and vs_1568.getType().hasName("AVFormatContext *")
and vret_1573.getType().hasName("int64_t")
and vs_1568.getParentScope+() = func
and vret_1573.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
