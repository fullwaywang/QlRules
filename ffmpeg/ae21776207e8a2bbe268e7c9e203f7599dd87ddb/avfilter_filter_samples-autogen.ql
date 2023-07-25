/**
 * @name ffmpeg-ae21776207e8a2bbe268e7c9e203f7599dd87ddb-avfilter_filter_samples
 * @id cpp/ffmpeg/ae21776207e8a2bbe268e7c9e203f7599dd87ddb/avfilter-filter-samples
 * @description ffmpeg-ae21776207e8a2bbe268e7c9e203f7599dd87ddb-libavfilter/avfilter.c-avfilter_filter_samples CVE-2012-0847
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_660, ExprStmt target_2, ExprStmt target_3, ArrayExpr target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof ArrayExpr
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_660
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="8"
		and target_0.getParent().(ForStmt).getStmt()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_1.getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vsamplesref_656, Variable vi_660, ExprStmt target_2, ArrayExpr target_1) {
		target_1.getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_1.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsamplesref_656
		and target_1.getArrayOffset().(VariableAccess).getTarget()=vi_660
		and target_1.getParent().(ForStmt).getStmt()=target_2
}

predicate func_2(Parameter vsamplesref_656, Variable vi_660, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_2.getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cur_buf"
		and target_2.getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("AVFilterLink *")
		and target_2.getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_660
		and target_2.getExpr().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getExpr().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsamplesref_656
		and target_2.getExpr().(FunctionCall).getArgument(1).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_660
		and target_2.getExpr().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_2.getExpr().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsamplesref_656
		and target_2.getExpr().(FunctionCall).getArgument(2).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_3(Variable vi_660, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_660
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Parameter vsamplesref_656, Variable vi_660, ArrayExpr target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vi_660, target_2, target_3, target_1)
and func_1(vsamplesref_656, vi_660, target_2, target_1)
and func_2(vsamplesref_656, vi_660, target_2)
and func_3(vi_660, target_3)
and vsamplesref_656.getType().hasName("AVFilterBufferRef *")
and vi_660.getType().hasName("int")
and vsamplesref_656.getFunction() = func
and vi_660.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
